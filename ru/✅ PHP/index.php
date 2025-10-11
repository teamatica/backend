<?php //@teamatica │ 0.0.0.0 │ 2025-10-01 23:59:59 UTC+00:00

declare(strict_types=1);

final readonly class Initial {
	public const O_NAME = '$2y$12$%%%%%';
	public const O_PASS = '$2y$12$%%%%%';
	public const S_BASE = 'https://teamatica.github.io/languages/';
	public const S_FILE = 'file.json';
	public const S_LIST = ['ru'];
	public const T_CORE = 2;
	public const T_DAYS = 60;
	public const T_NAME = 'Teamatica';
	public const T_PATH = '%%%%%';
	public const T_SIZE = 1 * 1024 * 1024;
	public string $fBase, $fRoot, $rCopy, $rData, $sLang;
	public function __construct(public string $aBase) {
		$this->fBase = $this->aBase . DIRECTORY_SEPARATOR . self::T_PATH;
		$this->fRoot = $this->fBase . DIRECTORY_SEPARATOR . 'bundle';
		$this->rCopy = $this->fRoot . DIRECTORY_SEPARATOR . 'backup';
		$this->rData = $this->fRoot . DIRECTORY_SEPARATOR . 'binary';
		$this->sLang = $this->aBase . DIRECTORY_SEPARATOR . 'languages';
	}
	public function aPath(): array {return [$this->fBase, $this->fRoot, $this->rCopy, $this->rData];}
	public function uCase(): string {return $this->rData . DIRECTORY_SEPARATOR . self::T_NAME . '.zip';}
	public function uList(): string {return $this->rData . DIRECTORY_SEPARATOR . self::T_NAME . '.sql';}
	public function uTemp(): string {return $this->rData . DIRECTORY_SEPARATOR . self::T_NAME . '.mfa';}
}

final readonly class Memento {public function __construct(public ?string $alphabet, public ?int $offset, public ?string $secret, public ?int $version, public bool $zipped) {}}

final readonly class Request {
	public function getPost(string $key, string|array|null $default = null): string|array|null {return $this->post[$key] ?? $default;}
	public static function getHeader(string $key, ?string $default = null): ?string {return $_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $key))] ?? $default;}
	public static function loadFrom(): self {return new self($_POST, $_FILES, $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');}
	private function __construct(public array $post, public array $files, public string $address) {}
}

final class Manager {
	public static function createDirectory(string $path, int $permissions = 0700): void {is_dir($path) || mkdir($path, $permissions, true) || throw new \RuntimeException("Failed to create directory: {$path}");}
	public static function initialize(Initial $initial): void {array_map(self::createDirectory(...), $initial->aPath());}
	public static function recursiveRemove(string $path, string $sandbox): void {
		if (!($sandboxPath = realpath($sandbox)) || !($realPath = realpath($path)) || $realPath === $sandboxPath || !str_starts_with($realPath, $sandboxPath . DIRECTORY_SEPARATOR)) return;
		if (!is_dir($realPath)) {
			unlink($realPath);
			return;
		}
		$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($realPath, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
		$files = iterator_to_array($iterator);
		array_walk($files, function($fileinfo) use ($sandboxPath) {
			$itemPath = $fileinfo->getRealPath();
			if ($itemPath === false || !str_starts_with($itemPath, $sandboxPath . DIRECTORY_SEPARATOR)) throw new \RuntimeException('Path traversal attempt at: ' . $fileinfo->getPathname());
			$fileinfo->isDir() ? rmdir($itemPath) : unlink($itemPath);
		});
		rmdir($realPath);
	}
}

class Alert extends Exception {public function __construct(string $message, int $code, public string $errorCode) {parent::__construct($message, $code);}}

class MFAService {
	public const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	public static function generateSecret(#[SensitiveParameter] string $hash, string $alphabet): string {return self::base32Encode(substr(hash('sha256', $hash, true), 0, 20), $alphabet);}
	public static function verifyCode(#[SensitiveParameter] string $secret, #[SensitiveParameter] string $code, int $digits, int $period, string $alphabet, int $offset): bool {return !(strlen($code) !== $digits || $period <= 0 || !in_array($digits, [6, 10], true)) && array_reduce([-1, 0, 1], fn($found, $i) => $found || hash_equals(self::generateCode($secret, (int)floor(time() / $period) + $i, $digits, $alphabet, $offset), $code), false);}
	private static function base32Decode(string $secret, string $alphabet): string {
		if (empty($secret = str_replace('=', '', $secret))) return '';
		if (strspn($secret, $alphabet) !== strlen($secret)) throw new \InvalidArgumentException('Invalid secret');
		return array_reduce(str_split($secret), function($acc, $char) use ($alphabet) {
			$acc['bits'] = ($acc['bits'] << 5) | strpos($alphabet, $char);
			if (($acc['length'] += 5) >= 8) {
				$acc['length'] -= 8;
				$acc['decoded'] .= chr(($acc['bits'] >> $acc['length']) & 255);
			}
			return $acc;
		}, ['decoded' => '', 'bits' => 0, 'length' => 0])['decoded'];
	}
	private static function base32Encode(string $data, string $alphabet): string {
		if (empty($data)) return '';
		$acc = array_reduce(str_split($data), function($acc, $char) use ($alphabet) {
			$acc['bits'] = ($acc['bits'] << 8) | ord($char);
			$acc['length'] += 8;
			while ($acc['length'] >= 5) {
				$acc['length'] -= 5;
				$acc['encoded'] .= $alphabet[($acc['bits'] >> $acc['length']) & 31];
			}
			return $acc;
		}, ['encoded' => '', 'bits' => 0, 'length' => 0]);
		if ($acc['length'] > 0) $acc['encoded'] .= $alphabet[($acc['bits'] << (5 - $acc['length'])) & 31];
		return $acc['encoded'] . str_repeat('=', (8 - (strlen($acc['encoded']) % 8)) % 8);
	}
	private static function generateCode(string $secret, int $slice, int $digits, string $alphabet, int $offset): string {
		$hmac = hash_hmac('sha1', pack('N', match ($digits) {6 => 0, 10 => $offset, default => throw new \InvalidArgumentException('Invalid code length')}) . pack('N', $slice), self::base32Decode($secret, $alphabet), true);
		return str_pad((string)((unpack('N', substr($hmac, ord($hmac[19]) & 0xf, 4))[1] & 0x7FFFFFFF) % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
	}
}

class SQLService {
	private array $connections = [];
	public function closeConnection(string $dsn): void {unset($this->connections['w_' . $dsn], $this->connections['r_' . $dsn]);}
	public function getConnection(string $dsn, bool $readOnly = false): PDO {
		return $this->connections[($readOnly ? 'r_' : 'w_') . $dsn] ??= (function() use ($dsn, $readOnly): PDO {
			try {
				$options = [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false, PDO::ATTR_TIMEOUT => 5] + ($readOnly ? [PDO::SQLITE_ATTR_OPEN_FLAGS => PDO::SQLITE_OPEN_READONLY] : []);
				$pdo = new PDO('sqlite:' . $dsn, null, null, $options);
				$readOnly || $pdo->exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
				return $pdo;
			} catch (PDOException $e) {
				error_log(Initial::T_NAME . " | ⛔ | Database connection failed ({$e->getMessage()})");
				throw new Alert('Service is temporarily unavailable', 503, 'x2');
			}
		})();
	}
}

class CodesService {
	private ?PDO $db = null;
	public function __construct(private readonly Initial $initial, private readonly SQLService $sqlService) {}
	public function cleanupTokens(array $activeHashes): void {match (empty($activeHashes)) {true => $this->getDB()->exec('DELETE FROM list'), false => $this->getDB()->prepare('DELETE FROM list WHERE user NOT IN (SELECT value FROM json_each(?))')->execute([json_encode(array_map(fn($id) => hash('sha256', (string)$id), $activeHashes))])};}
	public function createToken(string $userID, #[SensitiveParameter] string $userLine, #[SensitiveParameter] string $userHash, #[SensitiveParameter] string $userKey): string {
		$nonce = random_bytes(12);
		($data = openssl_encrypt(json_encode(['uid' => $userID, 'rnd' => bin2hex(random_bytes(32))]), 'aes-256-gcm', $userKey, OPENSSL_RAW_DATA, $nonce, $tag, $userHash, 16)) !== false || throw new Exception('Encryption failed');
		return [$this->saveToken($userLine, $token = base64_encode($nonce . $data . $tag)), $token][1];
	}
	public function getToken(string $userLine): ?string {return $this->queryUser($userLine) ?: null;}
	public function isReady(string $userLine): bool {return $this->queryUser($userLine, '1') !== false;}
	public function resetConnection(): void {
		$this->sqlService->closeConnection($this->initial->uTemp());
		$this->db = null;
	}
	public function revokeToken(string $userLine): void {$this->getDB()->prepare('UPDATE list SET token = NULL WHERE user = ?')->execute([$userLine]);}
	public function setupSchema(PDO $connection): void {$connection->exec('CREATE TABLE IF NOT EXISTS list (user TEXT PRIMARY KEY, token TEXT) WITHOUT ROWID');}
	public function validateToken(#[SensitiveParameter] string $token, string $userID, #[SensitiveParameter] string $userLine, #[SensitiveParameter] string $userHash, #[SensitiveParameter] string $userKey): bool {return match (true) {($stored = $this->getToken($userLine)) === null => false, !hash_equals($stored, hash('sha256', $token)) => false, ($decoded = base64_decode($token, true)) === false => false, strlen($decoded) < 28 => false, ($decrypted = openssl_decrypt(substr($decoded, 12, -16), 'aes-256-gcm', $userKey, OPENSSL_RAW_DATA, substr($decoded, 0, 12), substr($decoded, -16), $userHash)) === false => false, ($payload = json_decode($decrypted, true)) === null => false, ($payload['uid'] ?? null) !== $userID => false, default => true};}
	private function getDB(): PDO {
		return $this->db ??= (function(): PDO {
			$db = $this->sqlService->getConnection($this->initial->uTemp());
			$db->exec('PRAGMA synchronous = OFF;');
			$this->setupSchema($db);
			return $db;
		})();
	}
	private function queryUser(string $userLine, string $column = 'token'): string|int|false|null {
		$allowedColumn = match ($column) {'token', '1' => $column, default => throw new \InvalidArgumentException("Invalid column specified: {$column}")};
		($stmt = $this->getDB()->prepare("SELECT {$allowedColumn} FROM list WHERE user = ?"))->execute([$userLine]);
		return $stmt->fetchColumn();
	}
	private function saveToken(string $userLine, string $token): void {$this->getDB()->prepare('INSERT INTO list (user, token) VALUES (?, ?) ON CONFLICT(user) DO UPDATE SET token = excluded.token')->execute([$userLine, hash('sha256', $token)]);}
}

class LangsService {
	public function __construct(private readonly Initial $initial) {}
	public function checkUpdate(): void {$this->getManifest() === null ? $this->initializeLanguages() : $this->synchronizeData(false);}
	public function initializeLanguages(): void {
		if (is_dir($this->initial->sLang)) Manager::recursiveRemove($this->initial->sLang, $this->initial->aBase);
		Manager::createDirectory($this->initial->sLang, 0700);
		$this->synchronizeData(true);
	}
	private function fetchFile(string ...$filenames): array {
		return empty($filenames) ? [] : array_reduce($filenames, function($results, $filename) {
			if ($curl = curl_init(Initial::S_BASE . $filename)) {
				curl_setopt_array($curl, [CURLOPT_FAILONERROR => false, CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 3, CURLOPT_RETURNTRANSFER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_TIMEOUT => 10, CURLOPT_USERAGENT => Initial::T_NAME]);
				$content = curl_exec($curl);
				$results[$filename] = (curl_getinfo($curl, CURLINFO_HTTP_CODE) === 200 && $content !== false) ? $content : (!error_log(Initial::T_NAME . ' | ❗ | Not found: ' . Initial::S_BASE . $filename) ? null : null);
				curl_close($curl);
			} else $results[$filename] = null;
			return $results;
		}, []);
	}
	private function filterFiles(array $allFiles): array {
		if (empty(Initial::S_LIST)) return [];
		$allowedMap = array_flip(array_map(fn($code) => strtolower($code) . '.txt', Initial::S_LIST));
		return array_values(array_filter($allFiles, fn($file) => isset($file->f) && isset($allowedMap[strtolower($file->f)])));
	}
	private function getManifest(): ?object {
		$path = $this->initial->sLang . DIRECTORY_SEPARATOR . Initial::S_FILE;
		$decoded = is_readable($path) ? json_decode(file_get_contents($path)) : null;
		if (is_object($decoded)) $decoded->files ??= [];
		return $decoded;
	}
	private function missingLanguages(array $remoteFiles): void {
		if (empty(Initial::S_LIST)) return;
		$missingNames = array_diff(array_map(fn($code) => strtolower($code) . '.txt', Initial::S_LIST), array_column($remoteFiles, 'f'));
		!empty($missingNames) && array_walk($missingNames, fn($missing) => error_log(Initial::T_NAME . ' | ❗ | Not found: ' . Initial::S_BASE . $missing));
	}
	private function pruneFiles(array $targetNames): int {
		$targetMap = array_flip($targetNames);
		return array_reduce(glob($this->initial->sLang . DIRECTORY_SEPARATOR . '*.txt') ?: [], fn($count, $path) => !isset($targetMap[basename($path)]) && is_writable($path) && unlink($path) ? $count + 1 : $count, 0);
	}
	private function synchronizeData(bool $isInitialization): void {
		(isset(($manifest = (($remoteManifest = $this->fetchFile(Initial::S_FILE)[Initial::S_FILE] ?? null) ? json_decode($remoteManifest) : null))->v, $manifest->f)) || (error_log(Initial::T_NAME . ' | ❗ | Not found or invalid: ' . Initial::S_BASE . Initial::S_FILE) && exit());
		$localManifest = $isInitialization ? null : $this->getManifest();
		$this->missingLanguages($manifest->f);
		$fileMap = array_column($localManifest->f ?? [], 'v', 'f');
		$fileList = array_filter($targetFiles = $this->filterFiles($manifest->f), fn($remoteFile) => $isInitialization || ($remoteFile->v > ($fileMap[$remoteFile->f] ?? -1)) || !is_readable($this->initial->sLang . DIRECTORY_SEPARATOR . $remoteFile->f));
		[$added, $updated] = !empty($fileList) ? (function() use ($fileList, $fileMap): array {
			$fetchedContents = $this->fetchFile(...array_column($fileList, 'f'));
			return array_reduce($fileList, fn($counts, $remoteFile) => !$this->verifyFile($remoteFile->f, $remoteFile->h, $fetchedContents[$remoteFile->f] ?? null) ? $counts : (isset($fileMap[$remoteFile->f]) ? [$counts[0], ++$counts[1]] : [++$counts[0], $counts[1]]), [0, 0]);
		})() : [0, 0];
		$pruned = $isInitialization ? 0 : $this->pruneFiles(array_column($targetFiles, 'f'));
		if ($added || $updated || $pruned || ($manifest->v > ($localManifest->v ?? -1))) {
			file_put_contents($this->initial->sLang . DIRECTORY_SEPARATOR . Initial::S_FILE, json_encode(['v' => $manifest->v, 'f' => $targetFiles], JSON_UNESCAPED_UNICODE));
			($logParts = array_filter(['added' => $added, 'pruned' => $pruned, 'updated' => $updated])) && error_log(Initial::T_NAME . ' | 🔄️ | Languages: ' . implode(', ', array_map(fn($v, $k) => "$k $v", $logParts, array_keys($logParts))));
		}
	}
	private function verifyFile(string $filename, string $expectedHash, ?string $content): bool {return match (true) {$content === null => false, !hash_equals($expectedHash, hash('sha256', $content)) => !error_log(Initial::T_NAME . ' | ❗ | Wrong file: ' . Initial::S_BASE . $filename), !mb_check_encoding($content, 'UTF-8') =>!error_log(Initial::T_NAME . ' | ⛔ | Invalid encoding: ' . Initial::S_BASE . $filename), default => file_put_contents($this->initial->sLang . DIRECTORY_SEPARATOR . $filename, $content) !== false};}
}

class UsersService {
	private ?Memento $stateCache = null;
	public function __construct(private readonly Initial $initial, private readonly SQLService $sqlService) {}
	public function createBase(string $newBase, array $sourceFiles, string $version, #[SensitiveParameter] string $secret, #[SensitiveParameter] ?string $alphabet, ?int $offset): void {$this->buildDatabase($newBase, $this->extractData($sourceFiles, $alphabet, $offset, $secret, $version));}
	public function getHash(int $row): ?string {
		if ($row <= 0 || !is_readable($this->initial->uList())) return null;
		($stmt = $this->getConnection($this->initial->uList(), true)->prepare('SELECT user FROM list WHERE rowid = ?'))->execute([$row]);
		return $stmt->fetchColumn() ?: null;
	}
	public function getState(): Memento {return $this->stateCache ??= $this->loadState();}
	public function invalidateCache(): void {$this->stateCache = null;}
	private function buildDatabase(string $newBase, array $data): void {
		if (file_exists($newBase)) unlink($newBase);
		$db = $this->getConnection($newBase);
		try {
			$db->beginTransaction();
			$db->exec('CREATE TABLE list (user TEXT)');
			$db->exec('CREATE TABLE data (alphabet TEXT NOT NULL, offset INTEGER NOT NULL, secret TEXT NOT NULL, version INTEGER NOT NULL)');
			if (!empty($data['hashes'])) $db->prepare('INSERT INTO list (user) SELECT value FROM json_each(?)')->execute([json_encode($data['hashes'])]);
			$db->prepare('INSERT INTO data (alphabet, offset, secret, version) VALUES (?, ?, ?, ?)')->execute([$data['alphabet'], $data['offset'], $data['secret'], $data['version']]);
			$db->commit();
		} catch (Throwable $e) {
			if ($db->inTransaction()) $db->rollBack();
			if (file_exists($newBase)) unlink($newBase);
			error_log(Initial::T_NAME . " | ⛔ | DB creation failed ({$e->getMessage()})");
			throw new Alert('Failed to build new user database', 500, 'x9');
		}
	}
	private function extractData(array $sourceFiles, ?string $alphabet, ?int $offset, string $secret, string $version): array {
		$cleanSecret = trim(strtoupper($secret));
		match (true) {!ctype_digit($version) => throw new Alert('Invalid data format in version field', 400, 'x6'), strlen($cleanSecret) !== 32 || preg_match('/[^' . MFAService::ABC . ']/', $cleanSecret) => throw new Alert('Invalid data format in secret field', 400, 'x8'), !is_string($alphabet) || strlen($alphabet) !== 32 || count(array_unique(str_split($alphabet))) !== 32 => throw new Alert('Invalid data format in alphabet field', 400, 'x5'), !is_int($offset) || $offset < 0 => throw new Alert('Invalid data format in offset field', 400, 'x5'), default => true};
		return ['hashes' => array_map(fn(string $line) => ($hash = trim($line)) === '' ? null : (password_get_info($hash)['algoName'] === 'bcrypt' ? $hash : throw new Alert('Invalid data format in hashList.txt', 400, 'x4')), explode("\n", ($sourceFiles['hashList.txt']['content'] ?? throw new Alert('File hashList.txt is missing or not readable', 500, 'x3')))), 'version' => (int)$version, 'secret' => $cleanSecret, 'alphabet' => $alphabet, 'offset' => $offset];
	}
	private function getConnection(string $dbPath): PDO {return $this->sqlService->getConnection($dbPath);}
	private function loadState(): Memento {
		$uListPath = $this->initial->uList();
		if (!file_exists($uListPath)) return new Memento(null, null, null, null, false);
		$data = $this->getConnection($uListPath, true)->query('SELECT alphabet, offset, secret, version FROM data LIMIT 1')->fetch(PDO::FETCH_ASSOC);
		return new Memento($data['alphabet'] ?? null, $data ? (int)$data['offset'] : null, $data['secret'] ?? null, $data ? (int)$data['version'] : null, file_exists($this->initial->uCase()));
	}
}

class UtilsService {
	public function __construct(private readonly Initial $initial, private readonly SQLService $sqlService, private readonly CodesService $codesService, private readonly UsersService $usersService) {}
	public function processUpload(Request $request, string $version, #[SensitiveParameter] string $secret, #[SensitiveParameter] ?string $alphabet, ?int $offset): void {
		$tempPath = dirname($this->initial->rData) . DIRECTORY_SEPARATOR . bin2hex(random_bytes(12));
		try {
			$newFolder = $this->prepareUpdate($request, $tempPath, $version, $secret, $alphabet, $offset);
			file_exists($this->initial->uCase()) ? $this->performUpdate($newFolder, $tempPath) : $this->initialActivation($newFolder);
			$this->usersService->invalidateCache();
		} finally {
			if (is_dir($tempPath)) Manager::recursiveRemove($tempPath, $this->initial->fBase);
		}
		try {
			$this->pruneBackups();
		} catch (\Throwable $e) {
			error_log(Initial::T_NAME . " | ❗ | Unable to prune ({$e->getMessage()})");
		}
	}
	public function streamFile(?string $token = null): void {
		$filePath = $this->initial->uCase();
		if (!file_exists($filePath) || !is_readable($filePath)) throw new Alert('Archive not found', 404, 'a6');
		header('Content-Disposition: attachment; filename="' . Initial::T_NAME . '.zip"');
		header('Content-Length: ' . filesize($filePath));
		header('Content-Transfer-Encoding: binary');
		header('Content-Type: application/zip');
		if ($token) header(Initial::T_NAME . ':' . $token);
		if (ob_get_level()) ob_end_clean();
		readfile($filePath);
		exit();
	}
	private function checkTokens(array $uploaded): void {
		if (($hashListContent = $uploaded['hashList.txt']['content'] ?? null) === null) return;
		$this->codesService->cleanupTokens([Initial::O_PASS, ...array_filter(explode("\n", trim($hashListContent)))]);
	}
	private function initialActivation(string $newFolder): void {
		if (is_dir($this->initial->rData)) Manager::recursiveRemove($this->initial->rData, $this->initial->aBase);
		if (!rename($newFolder, $this->initial->rData)) throw new Alert('Failed to activate initial version', 500, 'b0');
	}
	private function performUpdate(string $newFolder, string $tempPath): void {
		(file_exists($lockFile = $this->initial->fBase . DIRECTORY_SEPARATOR . 'update.lock') && (time() - filemtime($lockFile)) > 5) && unlink($lockFile);
		($lock = fopen($lockFile, 'c')) && flock($lock, LOCK_EX | LOCK_NB) or (fclose($lock) and throw new Alert('Another update process is already running', 409, 'b0'));
		try {
			$this->sqlService->closeConnection($this->initial->uList());
			$this->sqlService->closeConnection($this->initial->uTemp());
			$this->codesService->resetConnection();
			$mfaTemp = $tempPath . DIRECTORY_SEPARATOR . basename($this->initial->uTemp());
			(!file_exists($this->initial->uTemp()) || rename($this->initial->uTemp(), $mfaTemp)) || throw new Alert('Failed to secure MFA state', 500, 'b0');
			$backupPath = str_replace('/', DIRECTORY_SEPARATOR, $this->initial->rCopy . '/' . date('Y/m/d/H-i-s/') . basename($this->initial->rData));
			is_dir(dirname($backupPath)) || mkdir(dirname($backupPath), 0700, true);
			rename($this->initial->rData, $backupPath) || (function() use ($mfaTemp) {
				file_exists($mfaTemp) && rename($mfaTemp, $this->initial->uTemp());
				throw new Alert('Failed to backup current data', 500, 'b5');
			})();
			$mfaPath = $backupPath . DIRECTORY_SEPARATOR . basename($this->initial->uTemp());
			$this->codesService->setupSchema($this->sqlService->getConnection($mfaPath));
			$this->sqlService->closeConnection($mfaPath);
			chmod($mfaPath, 0600) || error_log(Initial::T_NAME . ' | ❗ | Failed to set secure permissions on backup MFA file: ' . $mfaPath);
			rename($newFolder, $this->initial->rData) || (function() use ($backupPath, $mfaTemp) {
				is_dir($backupPath) && rename($backupPath, $this->initial->rData);
				file_exists($mfaTemp) && rename($mfaTemp, $this->initial->uTemp());
				throw new Alert('Failed to activate new version', 500, 'b6');
			})();
			(!file_exists($mfaTemp) || rename($mfaTemp, $this->initial->uTemp())) || (function() use ($backupPath) {
				is_dir($backupPath) && rename($backupPath, $this->initial->rData);
				throw new Alert('Failed to restore MFA state', 500, 'b0');
			})();
		} finally {
			flock($lock, LOCK_UN);
			fclose($lock);
			file_exists($lockFile) && unlink($lockFile);
		}
	}
	private function prepareUpdate(Request $request, string $tempPath, string $version, string $secret, ?string $alphabet, ?int $offset): string {
		$uploaded = $this->validateFiles($request, $tempPath);
		$this->checkTokens($uploaded);
		$newFolder = $tempPath . DIRECTORY_SEPARATOR . 'new';
		if (!mkdir($newFolder, 0700, true)) throw new Alert('Cannot create new folder', 500, 'b4');
		$tempSQL = $newFolder . DIRECTORY_SEPARATOR . basename($this->initial->uList());
		$this->usersService->createBase($tempSQL, $uploaded, $version, $secret, $alphabet, $offset);
		if (!chmod($tempSQL, 0600)) throw new Alert('Cannot create new SQL', 500, 'b4');
		$tempZIP = $newFolder . DIRECTORY_SEPARATOR . basename($this->initial->uCase());
		if (!rename($uploaded['fileBase.zip']['path'], $tempZIP)) throw new Alert('Failed to promote ZIP file', 500, 'b6');
		if (!chmod($tempZIP, 0600)) throw new Alert('Cannot create new ZIP', 500, 'b4');
		return $newFolder;
	}
	private function pruneBackups(): void {
		if (($backupPath = realpath($this->initial->rCopy)) === false) return;
		$dayDirs = glob($backupPath . '/*/*/*', GLOB_ONLYDIR) ?: [];
		$cutoffDate = (new \DateTimeImmutable())->modify('-' . Initial::T_DAYS . ' days');
		$prunedCount = array_reduce($dayDirs, function($count, $dir) use ($backupPath, $cutoffDate) {
			$dateStr = str_replace(DIRECTORY_SEPARATOR, '-', substr($dir, strlen($backupPath) + 1));
			$dirDate = \DateTimeImmutable::createFromFormat('Y-m-d', $dateStr);
			if ($dirDate === false) {
				error_log(Initial::T_NAME . " | ❗ | Invalid date format: {$dateStr}");
				return $count;
			}
			if ($dirDate < $cutoffDate) {
				Manager::recursiveRemove($dir, $this->initial->fBase);
				$parent = dirname($dir);
				while (($parentPath = realpath($parent)) && $parentPath !== $backupPath && count(scandir($parent)) === 2) {
					rmdir($parent);
					$parent = dirname($parent);
				}
				return $count + 1;
			}
			return $count;
		}, 0);
		if ($prunedCount > 0) error_log(Initial::T_NAME . " | ♻️ | Pruned backups from {$prunedCount} day" . ($prunedCount > 1 ? 's' : ''));
	}
	private function validateFiles(Request $request, string $tempPath): array {
		Manager::createDirectory($tempPath);
		Manager::createDirectory($tempDir = $tempPath . DIRECTORY_SEPARATOR . 'temp');
		$files = $request->files['file'] ?? throw new Alert('Invalid data format', 400, 'b7');
		(is_array($files) && isset($files['name']) && count($files['name']) === 2) || throw new Alert('Invalid data format', 400, 'b7');
		disk_free_space(dirname($tempPath)) > (Initial::T_SIZE * 100) || throw new Alert('Not enough disk space', 507, 'b9');
		return array_reduce(range(0, 1), function($validated, $i) use ($files, $tempDir) {
			$filename = in_array($name = basename($files['name'][$i]), ['fileBase.zip', 'hashList.txt'], true) ? $name : throw new Alert('Invalid new file: ' . $name, 400, 'b2');
			$files['error'][$i] === UPLOAD_ERR_OK || throw new Alert("Upload error: {$files['error'][$i]}", 500, 'b6');
			$files['size'][$i] <= Initial::T_SIZE || throw new Alert('File too large', 413, 'b3');
			move_uploaded_file($files['tmp_name'][$i], $file = $tempDir . DIRECTORY_SEPARATOR . $filename) && is_readable($file) || throw new Alert('Cannot process temp file', 500, 'b1');
			$content = null;
			$filename === 'fileBase.zip' ? (str_starts_with(file_get_contents($file, false, null, 0, 4), "PK\x03\x04") || throw new Alert('Invalid ZIP', 415, 'b2')) : (mb_check_encoding($content = file_get_contents($file), 'UTF-8') || throw new Alert('Invalid TXT', 415, 'b2'));
			return $validated + [$filename => ['path' => $file, 'content' => $content]];
		}, []);
	}
}

final class Application {
	private ?Memento $state = null;
	private ?bool $isFirst = null;
	private ?string $signatureKey = null;
	public function __construct(private readonly Initial $initial, private readonly Request $request, private readonly CodesService $codesService, private readonly LangsService $langsService, private readonly UsersService $usersService, private readonly UtilsService $utilsService) {}
	public function run(): void {
		header_remove('X-Powered-By');
		if ($_SERVER['REQUEST_METHOD'] === 'GET') {
			header('Location: /', true, 302);
			exit();
		}
		try {
			$this->checkEnvironment();
			if ($_SERVER['REQUEST_METHOD'] === 'HEAD') {
				http_response_code(200);
				exit();
			}
			header('Cache-Control: no-store, no-cache, must-revalidate');
			if (!($this->isFirst())) $this->getClient();
			match (true) {$this->request->getPost('update') !== null => $this->handleUpdate(), $this->request->getPost('upload') !== null => $this->handleUpload(), $this->isFirst() => $this->langsService->initializeLanguages(), default => exit()};
		} catch (Alert $e) {
			$this->sendResponse($e->errorCode, $e->getCode(), $e);
		} catch (Throwable $e) {
			error_log(Initial::T_NAME . ' | ⛔ | ' . sprintf("Uncaught %s: \"%s\" in %s:%d", $e::class, $e->getMessage(), $e->getFile(), $e->getLine()));
			$this->sendResponse('x1', 500, $e);
		}
	}
	public static function boot(): self {return new self($initial = new Initial(__DIR__), Request::loadFrom(), $codesService = new CodesService($initial, $sqlService = new SQLService()), new LangsService($initial), $usersService = new UsersService($initial, $sqlService), new UtilsService($initial, $sqlService, $codesService, $usersService));}
	private function authenticateRequest(#[SensitiveParameter] array $payload): array {
		$isOperator = !ctype_digit((string)($payload['i'] ?? ''));
		[$userID, $passwordHash] = match ($isOperator) {true => [0, Initial::O_PASS], false => [(int)$payload['i'], $this->usersService->getHash((int)$payload['i']) ?? throw new Alert("ID #{$payload['i']}: not found", 404, 'a5')]};
		if (!password_verify((string)($payload['p'] ?? ''), $passwordHash) || ($isOperator && !password_verify((string)($payload['i'] ?? ''), Initial::O_NAME))) throw new Alert("ID #{$userID}: authentication failed", 401, 'a1');
		return ['userID' => $userID, 'isOperator' => $isOperator, 'passwordHash' => $passwordHash];
	}
	private function checkEnvironment(): void {
		$missing = array_filter(['ctype', 'curl', 'hash', 'json', 'mbstring', 'openssl', 'pcre', 'pdo_sqlite'], fn($ext) => !extension_loaded($ext));
		match (true) {version_compare(PHP_VERSION, '8.2.0', '<') => throw new Alert('PHP: unsupported version', 501, 'x0'), !empty($missing) => throw new Alert('PHP: ' . implode(', ', $missing), 501, 'x0'), ini_parse_quantity(ini_get('upload_max_filesize')) < Initial::T_SIZE => throw new Alert('PHP: upload_max_filesize is too small', 501, 'x0'), ini_parse_quantity(ini_get('post_max_size')) < Initial::T_SIZE => throw new Alert('PHP: post_max_size is too small', 501, 'x0'), default => true};
	}
	private function getClient(): void {
		if (($state = $this->getState())->secret === null) return;
		$token = $this->request->getPost('unbolt');
		$token === null || MFAService::verifyCode($state->secret, (string)$token, 10, 6, $state->alphabet ?? throw new Alert('Unbolt alphabet not configured', 500, 'x5'), $state->offset ?? throw new Alert('Unbolt offset not configured', 500, 'x5')) || throw new Alert('Authentication required', 401, 'a7');
	}
	private function getKey(): ?string {return $this->signatureKey ??= (($s = $this->getState()->secret) === null ? null : hash('sha256', gmdate('Y-m-d') . $s, true));}
	private function getPayload(string $postKey): array {return (is_string($payload = $this->request->getPost($postKey)) && $payload !== '') ? ['raw' => $payload, 'decoded' => $this->validatePayload($payload)] : throw new Alert('Invalid payload', 400, 'v1');}
	private function getState(): Memento {return $this->state ??= $this->usersService->getState();}
	private function handleFailure(string $userLine, string $userID, ?string $totpCode): never {
		$this->codesService->revokeToken($userLine);
		throw new Alert("ID #{$userID}: " . (($totpCode === null || $totpCode === '') ? 'MFA entry request sent' : 'invalid token'), 401, (($totpCode === null || $totpCode === '') ? 'q2' : 'q1'));
	}
	private function handleUpdate(): void {
		['raw' => $rawPayload, 'decoded' => $payload] = $this->getPayload('update');
		$state = $this->getState();
		empty($payload['p']) && ($this->sendResponse((((!ctype_digit((string)($payload['i'] ?? ''))) && password_verify((string)($payload['i'] ?? ''), Initial::O_NAME)) ? 'b' : 'a') . ':' . ($state->zipped ? '1' : '0') . (!$this->isFirst() ? '1' : '0')) || true) && exit();
		$this->verifySignature($rawPayload, Request::getHeader('X-Signature'));
		$user = $this->authenticateRequest($payload);
		$clientVersion = (int)($payload['v'] ?? 0);
		$serverVersion = $state->version ?? throw new Alert('Version not found', 404, 'a2');
		$mfaResult = ($serverVersion > 0 || (!$this->isFirst() && $user['isOperator'] && $clientVersion > -2)) ? $this->processMFA((string)$user['userID'], $user['passwordHash'], $payload['t'] ?? null, $user['isOperator'] ? (string)$payload['i'] : (string)$user['userID'], $payload['p'], $payload['h'] ?? null) : ['token' => null];
		if (isset($mfaResult['o'])) {
			$this->sendResponse($mfaResult['o']);
			return;
		}
		($newToken = $mfaResult['token'] ?? null) && error_log(Initial::T_NAME . " | 🔐 | ID #{$user['userID']}: token renewed | " . $this->request->address);
		($serverVersion === $clientVersion) && (($newToken ? header(Initial::T_NAME . ':' . $newToken) : null) || true) && $this->sendResponse('a3') && exit();
		error_log(Initial::T_NAME . " | ✅ | ID #{$user['userID']}: update sent | " . $this->request->address);
		$this->utilsService->streamFile($newToken);
	}
	private function handleUpload(): void {
		if (Initial::T_DAYS < 6) throw new Alert('Invalid backup retention period', 500, 'b8');
		['raw' => $rawPayload, 'decoded' => $payload] = $this->getPayload('upload');
		Manager::initialize($this->initial);
		$this->verifySignature($rawPayload, Request::getHeader('X-Signature'));
		$user = $this->authenticateRequest($payload);
		if (!isset($payload['a'], $payload['o'], $payload['s'], $payload['v'])) throw new Alert('Missing required data fields', 400, 'v6');
		$newToken = null;
		if (!$this->isFirst() && (is_dir($this->initial->rData) || !file_exists($this->initial->uCase()))) {
			$mfaResult = $this->processMFA('0', Initial::O_PASS, $payload['t'] ?? null, (string)($payload['i'] ?? ''), (string)($payload['p'] ?? ''), $payload['h'] ?? null);
			isset($mfaResult['o']) && ($this->sendResponse($mfaResult['o']) || exit());
			($newToken = $mfaResult['token'] ?? null) && header(Initial::T_NAME . ':' . $newToken);
		}
		$newToken && error_log(Initial::T_NAME . " | 🔐 | ID #{$user['userID']}: token renewed | " . $this->request->address);
		$this->utilsService->processUpload($this->request, (string)$payload['v'], (string)$payload['s'], (string)$payload['a'], (int)$payload['o']);
		$this->langsService->checkUpdate();
		error_log(Initial::T_NAME . " | ☑️ | ID #{$user['userID']}: upload received | " . $this->request->address);
		$this->sendResponse('a', 201);
	}
	private function isFirst(): bool {return $this->isFirst ??= !file_exists($this->initial->uList());}
	private function processMFA(string $userID, #[SensitiveParameter] string $passwordHash, #[SensitiveParameter] ?string $totpCode, ?string $userName, #[SensitiveParameter] ?string $userCode, #[SensitiveParameter] ?string $clientHash): array {
		$userLine = hash('sha256', $passwordHash);
		$userKey = hash_hkdf('sha256', (string)$userName . "\0" . (string)$userCode, 32, '', (string)$clientHash);
		if ($totpCode && strlen($totpCode) > 6) return $this->codesService->validateToken($totpCode, $userID, $userLine, $passwordHash, $userKey) ? ['token' => $this->codesService->createToken($userID, $userLine, $passwordHash, $userKey)] : $this->handleFailure($userLine, $userID, $totpCode);
		$mfaSecret = MFAService::generateSecret($passwordHash . $clientHash, MFAService::ABC);
		return match ([$this->codesService->isReady($userLine), $totpCode && strlen($totpCode) === 6 && ctype_digit($totpCode) && MFAService::verifyCode($mfaSecret, $totpCode, 6, 30, MFAService::ABC, 0)]) {[false, false] => ['o' => 'otpauth://totp/' . Initial::T_NAME . ":{$userID}?secret=" . $mfaSecret . "&issuer=" . Initial::T_NAME], [true, false]  => $this->handleFailure($userLine, $userID, $totpCode), default => ['token' => $this->codesService->createToken($userID, $userLine, $passwordHash, $userKey)]};
	}
	private function sendResponse(string|array $data, int $httpCode = 200, ?Throwable $e = null): void {
		$e && error_log(Initial::T_NAME . ' | ' . (($data === 'q2') ? '🔒' : (($httpCode >= 500) ? '⛔' : '🚫')) . ' | ' . $e->getMessage() . " ({$data}) | " . $this->request->address);
		http_response_code($httpCode);
		header('Content-Type: application/json; charset=UTF-8');
		$response = json_encode((is_string($data) ? ['r' => $data] : $data) + ['w' => time()], JSON_UNESCAPED_SLASHES);
		($key = $this->getKey()) && header('X-Signature:' . base64_encode(hash_hmac('sha256', $response, $key, true)));
		echo $response;
		$e && exit();
	}
	private function validatePayload(#[SensitiveParameter] string $rawPayload): array {
		strlen($rawPayload) < 600 || throw new Alert('Invalid JSON', 400, 'v1');
		$payload = json_decode($rawPayload, true);
		is_array($payload) || throw new Alert('Payload is not JSON', 400, 'v2');
		$userID = $payload['i'] ?? '-1';
		match (true) {($payload['c'] ?? null) !== Initial::T_CORE => throw new Alert("ID #{$userID}: wrong version", 400, 'v3'), isset($payload['p']) && (!isset($payload['w']) || !is_int($payload['w'])) => throw new Alert("ID #{$userID}: invalid timestamp", 400, 'v4'), isset($payload['w']) && abs(time() - $payload['w']) > 30 => throw new Alert("ID #{$userID}: request has expired", 408, 'v5'), default => true};
		return $payload;
	}
	private function verifySignature(#[SensitiveParameter] string $rawPayload, #[SensitiveParameter] ?string $clientSignature): void {
		if (($key = $this->getKey()) === null) {
			$this->isFirst() || throw new Alert('Cannot generate signature key', 500, 's1');
			return;
		}
		$decodedSignature = base64_decode($clientSignature ?? throw new Alert('Signature is missing', 400, 's2'), true) ?: throw new Alert('Invalid signature format', 400, 's3');
		hash_equals(hash_hmac('sha256', $rawPayload, $key, true), $decodedSignature) || throw new Alert('Invalid signature', 401, 's4');
	}
}

Application::boot()->run();

?>