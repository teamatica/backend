<?php //@teamatica │ 0.0.0.0 │ 10.01.2025 23:59:59 UTC+00:00

declare(strict_types=1);

final class Initial {
	public const O_NAME = '$2y$12$%%%%%';
	public const O_PASS = '$2y$12$%%%%%';
	public const S_BASE = 'https://teamatica.github.io/languages/';
	public const S_FILE = 'file.json';
	public const S_LIST = ['en', 'kk', 'ru', 'uk'];
	public const T_CORE = 2;
	public const T_DAYS = 60;
	public const T_NAME = 'Teamatica';
	public const T_PATH = '%%%%%';
	public const T_SIZE = 1 * 1024 * 1024;
	private ?string $fBase = null;
	private ?string $fRoot = null;
	private ?string $rCopy = null;
	private ?string $rData = null;
	private ?string $sLang = null;
	public function __construct(public string $aBase) {}
	public function aPath(): array {return [$this->fBase(), $this->fRoot(), $this->rCopy(), $this->rData()];}
	public function fBase(): string {return $this->fBase ??= $this->aBase . DIRECTORY_SEPARATOR . self::T_PATH;}
	public function fRoot(): string {return $this->fRoot ??= $this->fBase() . DIRECTORY_SEPARATOR . 'bundle';}
	public function rCopy(): string {return $this->rCopy ??= $this->fRoot() . DIRECTORY_SEPARATOR . 'backup';}
	public function rData(): string {return $this->rData ??= $this->fRoot() . DIRECTORY_SEPARATOR . 'binary';}
	public function sLang(): string {return $this->sLang ??= $this->aBase . DIRECTORY_SEPARATOR . 'languages';}
	public function uCase(): string {return $this->rData() . DIRECTORY_SEPARATOR . self::T_NAME . '.zip';}
	public function uList(): string {return $this->rData() . DIRECTORY_SEPARATOR . self::T_NAME . '.sql';}
	public function uTemp(): string {return $this->rData() . DIRECTORY_SEPARATOR . self::T_NAME . '.mfa';}
}

final class Manager {
	public static function createDirectory(string $path, int $permissions = 0700): void {
		if (is_dir($path)) return;
		if (!mkdir($path, $permissions, true)) throw new \RuntimeException("Failed to create directory: {$path}");
	}
	public static function initialize(Initial $initial): void {foreach ($initial->aPath() as $path) self::createDirectory($path);}
	public static function recursiveRemove(string $path, string $sandbox): void {
		$sandboxPath = realpath($sandbox);
		$realPath = realpath($path);
		if (!$sandboxPath || !$realPath || $realPath === $sandboxPath || !str_starts_with($realPath, $sandboxPath . DIRECTORY_SEPARATOR)) return;
		if (!is_dir($realPath)) {
			unlink($realPath);
			return;
		}
		$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($realPath, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
		foreach ($files as $fileinfo) {
			$itemPath = $fileinfo->getRealPath();
			if ($itemPath === false || !str_starts_with($itemPath, $sandboxPath . DIRECTORY_SEPARATOR)) {
				error_log(Initial::T_NAME . ' | ⛔ | Path traversal attempt at: ' . $fileinfo->getPathname());
				return;
			}
			$fileinfo->isDir() ? rmdir($itemPath) : unlink($itemPath);
		}
		rmdir($realPath);
	}
}

final class Request {
	public function getPost(string $key, mixed $default = null): mixed {return $this->post[$key] ?? $default;}
	public static function getHeader(string $key, ?string $default = null): ?string {return $_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $key))] ?? $default;}
	public static function loadFrom(): self {return new self($_POST, $_FILES, $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');}
	private function __construct(public readonly array $post, public readonly array $files, public readonly string $address) {}
}

class Alert extends Exception {public function __construct(string $message, int $code, public string $errorCode) {parent::__construct($message, $code);}}

class MFAService {
	public const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	public const XYZ = '%%%%%';
	public static function generateSecret(string $hash, string $alphabet): string {return self::base32Encode(substr(hash('sha256', $hash, true), 0, 20), $alphabet);}
	public static function verifyCode(string $secret, string $code, int $digits, int $period, string $alphabet): bool {
		if (strlen($code) !== $digits || $period <= 0) return false;
		try {
			for ($i = -1; $i <= 1; $i++) if (hash_equals(self::generateCode($secret, ((int)floor(time() / $period)) + $i, $digits, $alphabet), $code)) return true;
		} catch (\InvalidArgumentException $e) {
			return false;
		}
		return false;
	}
	private static function base32Decode(string $secret, string $alphabet): string {
		$secret = str_replace('=', '', $secret);
		if (empty($secret)) return '';
		if (strspn($secret, $alphabet) !== strlen($secret)) throw new \InvalidArgumentException('Invalid secret');
		$decoded = '';
		$bits = 0;
		$length = 0;
		foreach (str_split($secret) as $char) {
			$value = strpos($alphabet, $char);
			$bits = ($bits << 5) | $value;
			$length += 5;
			if ($length >= 8) {
				$length -= 8;
				$decoded .= chr(($bits >> $length) & 255);
			}
		}
		return $decoded;
	}
	private static function base32Encode(string $data, string $alphabet): string {
		if (empty($data)) return '';
		$encoded = '';
		$bits = 0;
		$length = 0;
		foreach (str_split($data) as $char) {
			$bits = ($bits << 8) | ord($char);
			$length += 8;
			while ($length >= 5) {
				$length -= 5;
				$encoded .= $alphabet[($bits >> $length) & 31];
			}
		}
		if ($length > 0) $encoded .= $alphabet[($bits << (5 - $length)) & 31];
		return $encoded . str_repeat('=', (8 - (strlen($encoded) % 8)) % 8);
	}
	private static function generateCode(string $secret, int $slice, int $digits, string $alphabet): string {
		if ($digits < 6 || $digits > 10) throw new \InvalidArgumentException('Invalid code length');
		$high = match ($digits) {6 => 0, 10 => %%%%%};
		$hmac = hash_hmac('sha1', pack('N', $high) . pack('N', $slice), self::base32Decode($secret, $alphabet), true);
		return str_pad((string)((unpack('N', substr($hmac, ord($hmac[19]) & 0xf, 4))[1] & 0x7FFFFFFF) % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
	}
}

class SQLService {
	private array $connections = [];
	public function closeConnection(string $dsn): void {
		if (isset($this->connections['w_' . $dsn])) unset($this->connections['w_' . $dsn]);
		if (isset($this->connections['r_' . $dsn])) unset($this->connections['r_' . $dsn]);
	}
	public function getConnection(string $dsn, bool $readOnly = false): PDO {
		$connectionKey = ($readOnly ? 'r_' : 'w_') . $dsn;
		if (!isset($this->connections[$connectionKey])) {
			try {
				$options = [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false, PDO::ATTR_TIMEOUT => 5];
				if ($readOnly) $options[PDO::SQLITE_ATTR_OPEN_FLAGS] = PDO::SQLITE_OPEN_READONLY;
				$pdo = new PDO('sqlite:' . $dsn, null, null, $options);
				if (!$readOnly) {
					$pdo->exec('PRAGMA journal_mode = WAL;');
					$pdo->exec('PRAGMA busy_timeout = 5000;');
				}
				$this->connections[$connectionKey] = $pdo;
			} catch (PDOException $e) {
				error_log(Initial::T_NAME . " | ⛔ | Database connection failed ({$e->getMessage()})");
				throw new Alert('Service is temporarily unavailable', 503, 'x2');
			}
		}
		return $this->connections[$connectionKey];
	}
}

class CodesService {
	private ?PDO $db = null;
	public function __construct(private Initial $initial, private SQLService $sqlService) {}
	public function cleanupTokens(array $activeHashes): void {
		$db = $this->getDB();
		if (empty($activeHashes)) {
			$db->exec('DELETE FROM codes');
			return;
		}
		$activeHashes = array_map(fn($id) => hash('sha256', (string)$id), $activeHashes);
		$db->prepare('DELETE FROM codes WHERE user NOT IN (' . implode(',', array_fill(0, count($activeHashes), '?')). ')')->execute($activeHashes);
	}
	public function createToken(string $userID, string $userLine, string $userHash, string $userKey): string {
		$nonce = random_bytes(12);
		$data = openssl_encrypt(json_encode(['uid' => $userID, 'rnd' => bin2hex(random_bytes(32))]), 'aes-256-gcm', $userKey, OPENSSL_RAW_DATA, $nonce, $tag, $userHash, 16);
		if ($data === false) throw new Exception('Encryption failed');
		$token = base64_encode($nonce . $data . $tag);
		$this->saveToken($userLine, $token);
		return $token;
	}
	public function getToken(string $userLine): ?string {
		$stmt = $this->getDB()->prepare('SELECT token FROM codes WHERE user = ?');
		$stmt->execute([$userLine]);
		return $stmt->fetchColumn() ?: null;
	}
	public function isReady(string $userLine): bool {
		$stmt = $this->getDB()->prepare('SELECT 1 FROM codes WHERE user = ?');
		$stmt->execute([$userLine]);
		return $stmt->fetchColumn() !== false;
	}
	public function resetConnection(): void {$this->db = null;}
	public function revokeToken(string $userLine): void {$this->getDB()->prepare('UPDATE codes SET token = NULL WHERE user = ?')->execute([$userLine]);}
	public function setupSchema(PDO $connection): void {$connection->exec('CREATE TABLE IF NOT EXISTS codes (user TEXT PRIMARY KEY, token TEXT)');}
	public function validateToken(string $token, string $userID, string $userLine, string $userHash, string $userKey): bool {
		$stored = $this->getToken($userLine);
		if ($stored === null || !hash_equals($stored, hash('sha256', $token))) return false;
		$decoded = base64_decode($token, true);
		if ($decoded === false || strlen($decoded) < 28) return false;
		$decrypted = openssl_decrypt(substr($decoded, 12, -16), 'aes-256-gcm', $userKey, OPENSSL_RAW_DATA, substr($decoded, 0, 12), substr($decoded, -16), $userHash);
		if ($decrypted === false) return false;
		$payload = json_decode($decrypted, true);
		return is_array($payload) && isset($payload['uid'], $payload['rnd']) && $payload['uid'] === $userID;
	}
	private function getDB(): PDO {
		if ($this->db === null) {
			$this->db = $this->sqlService->getConnection($this->initial->uTemp());
			$this->setupSchema($this->db);
		}
		return $this->db;
	}
	private function saveToken(string $userLine, string $token): void {$this->getDB()->prepare('INSERT INTO codes (user, token) VALUES (?, ?) ON CONFLICT(user) DO UPDATE SET token = excluded.token')->execute([$userLine, hash('sha256', $token)]);}
}

class LangsService {
	public function __construct(private Initial $initial) {}
	public function checkUpdate(): void {
		if ($this->getManifest() === null) {
			$this->initializeLanguages();
		} else {
			$this->synchronizeData(false);
		}
	}
	public function initializeLanguages(): void {
		if (is_dir($this->initial->sLang())) Manager::recursiveRemove($this->initial->sLang(), $this->initial->aBase);
		Manager::createDirectory($this->initial->sLang(), 0700);
		$this->synchronizeData(true);
	}
	private function fetchFile(string ...$filenames): array {
		if (empty($filenames)) return [];
		$results = [];
		foreach ($filenames as $filename) {
			$curlInit = curl_init(Initial::S_BASE . $filename);
			if ($curlInit === false) {
				$results[$filename] = null;
				continue;
			}
		curl_setopt_array($curlInit, [CURLOPT_FAILONERROR => false, CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 3, CURLOPT_RETURNTRANSFER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_TIMEOUT => 10, CURLOPT_USERAGENT => Initial::T_NAME]);
		$content = curl_exec($curlInit);
		$httpCode = curl_getinfo($curlInit, CURLINFO_HTTP_CODE);
		if ($httpCode === 200 && $content !== false) {
			$results[$filename] = $content;
		} else {
			$results[$filename] = null;
			error_log(Initial::T_NAME . ' | ❗ | Not found: ' . Initial::S_BASE . $filename);
		}
		curl_close($curlInit);
		}
		return $results;
	}
	private function filterFiles(array $allFiles): array {
		if (empty(Initial::S_LIST)) return [];
		$allowedMap = array_flip(array_map(fn($code) => strtolower($code) . '.txt', Initial::S_LIST));
		return array_values(array_filter($allFiles, fn($file) => isset($file->f) && isset($allowedMap[strtolower($file->f)])));
	}
	private function getManifest(): ?object {
		$path = $this->initial->sLang() . DIRECTORY_SEPARATOR . Initial::S_FILE;
		if (!is_readable($path)) return null;
		$content = file_get_contents($path);
		$decoded = $content ? json_decode($content) : null;
		if (is_object($decoded) && !isset($decoded->files)) $decoded->files = [];
		return $decoded;
	}
	private function missingLanguages(array $remoteFiles): void {
		if (empty(Initial::S_LIST)) return;
		$missingNames = array_diff(array_map(fn($code) => strtolower($code) . '.txt', Initial::S_LIST), array_column($remoteFiles, 'f'));
		if (!empty($missingNames)) foreach($missingNames as $missing) error_log(Initial::T_NAME . ' | ❗ | Not found: ' . Initial::S_BASE . $missing);
	}
	private function pruneFiles(array $targetNames): int {
		$prunedCount = 0;
		$targetMap = array_flip($targetNames);
		foreach ((glob($this->initial->sLang() . DIRECTORY_SEPARATOR . '*.txt') ?: []) as $path) if (!isset($targetMap[basename($path)]) && is_writable($path) && unlink($path)) $prunedCount++;
		return $prunedCount;
	}
	private function synchronizeData(bool $isInitialization): void {
		$localManifest = $isInitialization ? null : $this->getManifest();
		$remoteManifest = $this->fetchFile(Initial::S_FILE)[Initial::S_FILE] ?? null;
		if ($remoteManifest === null) {
			error_log(Initial::T_NAME . ' | ❗ | Not found: ' . Initial::S_BASE . Initial::S_FILE);
			return;
		}
		$manifest = json_decode($remoteManifest);
		if (!is_object($manifest) || !isset($manifest->v) || !isset($manifest->f)) {
			error_log(Initial::T_NAME . ' | ❗ | Invalid data format: ' . Initial::S_BASE . Initial::S_FILE);
			return;
		}
		$this->missingLanguages($manifest->f);
		$targetFiles = $this->filterFiles($manifest->f);
		$fileMap = $localManifest->f ?? [];
		if (!empty($fileMap)) $fileMap = array_column($fileMap, 'v', 'f');
		$fileList = [];
		foreach ($targetFiles as $remoteFile) if ($isInitialization || ($remoteFile->v > ($fileMap[$remoteFile->f] ?? -1)) || !is_readable($this->initial->sLang() . DIRECTORY_SEPARATOR . $remoteFile->f)) $fileList[] = $remoteFile;
		$addedCount = 0;
		$updatedCount = 0;
		if (!empty($fileList)) {
			$fetchedContents = $this->fetchFile(...array_column($fileList, 'f'));
			foreach ($fileList as $remoteFile) if ($this->verifyFile($remoteFile->f, $remoteFile->h, $fetchedContents[$remoteFile->f] ?? null)) isset($fileMap[$remoteFile->f]) ? $updatedCount++ : $addedCount++;
		}
		$prunedCount = $isInitialization ? 0 : $this->pruneFiles(array_column($targetFiles, 'f'));
		if ($addedCount > 0 || $updatedCount > 0 || $prunedCount > 0 || ($manifest->v > ($localManifest->v ?? -1))) {
			file_put_contents($this->initial->sLang() . DIRECTORY_SEPARATOR . Initial::S_FILE, json_encode(['v' => $manifest->v, 'f' => $targetFiles], JSON_UNESCAPED_UNICODE));
			$logParts = array_filter(['added' => $addedCount, 'updated' => $updatedCount, 'pruned' => $prunedCount]);
			if (!empty($logParts)) error_log(Initial::T_NAME . ' | 🔄️ | Languages synchronized (' . implode(', ', array_map(fn($v, $k) => "$k $v", $logParts, array_keys($logParts))) . ')');
		}
	}
	private function verifyFile(string $filename, string $expectedHash, ?string $content): bool {
		if ($content === null) return false;
		if (!hash_equals($expectedHash, hash('sha256', $content))) {
			error_log(Initial::T_NAME . ' | ❗ | Wrong file: ' . Initial::S_BASE . $filename);
			return false;
		}
		if (!mb_check_encoding($content, 'UTF-8')) {
			error_log(Initial::T_NAME . ' | ⛔ | Invalid encoding: ' . Initial::S_BASE . $filename);
			return false;
		}
		file_put_contents($this->initial->sLang() . DIRECTORY_SEPARATOR . $filename, $content);
		return true;
	}
}

class UsersService {
	private ?string $cachedSecret = null;
	public function __construct(private Initial $initial, private SQLService $sqlService) {}
	public function createBase(string $newBase, array $sourceFiles): void {$this->buildDatabase($newBase, $this->extractData($sourceFiles));}
	public function getHash(int $row): ?string {
		if ($row <= 0 || !is_readable($this->initial->uList())) return null;
		$stmt = $this->getConnection($this->initial->uList(), true)->prepare('SELECT bcrypt FROM list WHERE rowid = ?');
		$stmt->execute([$row]);
		return $stmt->fetchColumn() ?: null;
	}
	public function getSecret(): ?string {
		if (!is_readable($this->initial->uList())) return null;
		return $this->cachedSecret ??= ($this->getConnection($this->initial->uList(), true)->query('SELECT totp FROM secret')->fetchColumn() ?: null);
	}
	public function getVersion(): ?int {
		if (!file_exists($this->initial->uList())) return null;
		$result = $this->getConnection($this->initial->uList(), true)->query('SELECT number FROM version')->fetchColumn();
		return $result === false ? null : (int)$result;
	}
	public function invalidateCache(): void {$this->cachedSecret = null;}
	private function buildDatabase(string $newBase, array $data): void {
		if (file_exists($newBase)) unlink($newBase);
		$db = $this->getConnection($newBase);
		try {
			$db->beginTransaction();
			$db->exec('CREATE TABLE list (bcrypt TEXT)');
			$db->exec('CREATE TABLE version (number INTEGER NOT NULL)');
			$db->exec('CREATE TABLE secret (totp TEXT NOT NULL)');
			$hashes = $db->prepare('INSERT INTO list (bcrypt) VALUES (?)');
			foreach ($data['hashes'] as $hash) $hashes->execute([$hash]);
			$db->prepare('INSERT INTO version (number) VALUES (?)')->execute([$data['version']]);
			$db->prepare('INSERT INTO secret (totp) VALUES (?)')->execute([$data['secret']]);
			$db->commit();
		} catch (Throwable $e) {
			if ($db->inTransaction()) $db->rollBack();
			if (file_exists($newBase)) unlink($newBase);
			error_log(Initial::T_NAME . " | ⛔ | DB creation failed ({$e->getMessage()})");
			throw new Alert('Failed to build new user database', 500, 'x9');
		}
	}
	private function extractData(array $sourceFiles): array {
		$hashListContent = $sourceFiles['hashList.txt']['content'] ?? null;
		if ($hashListContent === null) throw new Alert('File hashList.txt is missing or not readable', 500, 'x3');
		$hashes = array_map(function(string $line) {
			$hash = trim($line);
			if ($hash === '') return null;
			if (password_get_info($hash)['algoName'] !== 'bcrypt') throw new Alert('Invalid data format in hashList.txt', 400, 'x4');
			return $hash;
		}, explode("\n", $hashListContent));
		$fileInfoContent = $sourceFiles['fileInfo.txt']['content'] ?? null;
		if ($fileInfoContent === null) throw new Alert('File fileInfo.txt is missing or not readable', 500, 'x5');
		$version = trim($fileInfoContent);
		if (!ctype_digit($version)) throw new Alert('Invalid data format in fileInfo.txt', 400, 'x6');
		$linkHeadContent = $sourceFiles['linkHead.txt']['content'] ?? null;
		if ($linkHeadContent === null) throw new Alert('File linkHead.txt is missing or not readable', 500, 'x7');
		$secret = trim(strtoupper(str_replace('=', '', $linkHeadContent)));
		if ((empty($secret) || preg_match('/[^' . MFAService::ABC . ']/', $secret) || strlen($secret) !== 32)) throw new Alert('Invalid data format in linkHead.txt', 400, 'x8');
		return ['hashes' => $hashes, 'version' => (int)$version, 'secret' => $secret];
	}
	private function getConnection(string $dbPath): PDO {return $this->sqlService->getConnection($dbPath);}
}

class UtilsService {
	public function __construct(private Initial $initial, private SQLService $sqlService, private CodesService $codesService, private UsersService $usersService) {}
	public function processUpload(Request $request): void {
		$tempPath = dirname($this->initial->rData()) . DIRECTORY_SEPARATOR . bin2hex(random_bytes(12));
		try {
			$newFolder = $this->prepareUpdate($request, $tempPath);
			if (file_exists($this->initial->uCase())) {
				$this->performUpdate($newFolder, $tempPath);
			} else {
				$this->initialActivation($newFolder);
			}
			$this->usersService->invalidateCache();
		} finally {
			if (is_dir($tempPath)) Manager::recursiveRemove($tempPath, $this->initial->fBase());
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
		$hashListContent = $uploaded['hashList.txt']['content'] ?? null;
		if ($hashListContent === null) return;
		$newData = array_filter(explode("\n", trim($hashListContent)));
		if (empty($newData)) $newData = [];
		$this->codesService->cleanupTokens(array_merge([Initial::O_PASS], $newData));
	}
	private function initialActivation(string $newFolder): void {
		if (is_dir($this->initial->rData())) Manager::recursiveRemove($this->initial->rData(), $this->initial->aBase);
		if (!rename($newFolder, $this->initial->rData())) throw new Alert('Failed to activate initial version', 500, 'b0');
	}
	private function performUpdate(string $newFolder, string $tempPath): void {
		$backupPath = null;
		$this->sqlService->closeConnection($this->initial->uList());
		$this->sqlService->closeConnection($this->initial->uTemp());
		$this->codesService->resetConnection();
		$mfaTemp = $tempPath . DIRECTORY_SEPARATOR . basename($this->initial->uTemp());
		if (file_exists($this->initial->uTemp())) {
			if (!rename($this->initial->uTemp(), $mfaTemp)) throw new Alert('Failed to secure MFA state', 500, 'b0');
		}
		$backupPath = str_replace('/', DIRECTORY_SEPARATOR, $this->initial->rCopy() . '/' . date('Y/m/d/H-i-s/') . basename($this->initial->rData()));
		if (!is_dir(dirname($backupPath))) mkdir(dirname($backupPath), 0700, true);
		if (!rename($this->initial->rData(), $backupPath)) {
			if (isset($mfaTemp) && file_exists($mfaTemp)) rename($mfaTemp, $this->initial->uTemp());
			throw new Alert('Failed to backup current data', 500, 'b5');
		}
		$mfaPath = $backupPath . DIRECTORY_SEPARATOR . basename($this->initial->uTemp());
		$this->codesService->setupSchema($this->sqlService->getConnection($mfaPath));
		$this->sqlService->closeConnection($mfaPath);
		chmod($mfaPath, 0600);
		if (!rename($newFolder, $this->initial->rData())) {
			if ($backupPath && is_dir($backupPath)) rename($backupPath, $this->initial->rData());
			if (isset($mfaTemp) && file_exists($mfaTemp)) rename($mfaTemp, $this->initial->uTemp());
			throw new Alert('Failed to activate new version', 500, 'b6');
		}
		if (isset($mfaTemp) && file_exists($mfaTemp)) {
			if (!rename($mfaTemp, $this->initial->uTemp())) {
				if ($backupPath && is_dir($backupPath)) rename($backupPath, $this->initial->rData());
				throw new Alert('Failed to restore MFA state', 500, 'b0');
			}
		}
	}
	private function prepareUpdate(Request $request, string $tempPath): string {
		$uploaded = $this->validateFiles($request, $tempPath);
		$this->checkTokens($uploaded);
		$newFolder = $tempPath . DIRECTORY_SEPARATOR . 'new';
		if (!mkdir($newFolder, 0700, true)) throw new Alert('Cannot create new folder', 500, 'b4');
		$tempSQL = $newFolder . DIRECTORY_SEPARATOR . basename($this->initial->uList());
		$this->usersService->createBase($tempSQL, $uploaded);
		chmod($tempSQL, 0600);
		$tempZIP = $newFolder . DIRECTORY_SEPARATOR . basename($this->initial->uCase());
		if (!rename($uploaded['fileBase.zip']['path'], $tempZIP)) throw new Alert('Failed to promote ZIP file', 500, 'b6');
		chmod($tempZIP, 0600);
		return $newFolder;
	}
	private function pruneBackups(): void {
		$backupPath = realpath($this->initial->rCopy());
		if ($backupPath === false || !($dayDirs = glob($backupPath . '/*/*/*', GLOB_ONLYDIR))) return;
		$cutoffDate = (new \DateTimeImmutable())->modify('-' . Initial::T_DAYS . ' days');
		$prunedCount = 0;
		foreach ($dayDirs as $dayDir) {
			$dateStr = str_replace(DIRECTORY_SEPARATOR, '-', substr($dayDir, strlen($backupPath) + 1));
			$dirDate = \DateTimeImmutable::createFromFormat('Y-m-d', $dateStr);
			if ($dirDate === false) error_log(Initial::T_NAME . " | ❗ | Invalid date format: {$dateStr}");
			if ($dirDate && $dirDate < $cutoffDate) {
				Manager::recursiveRemove($dayDir, $this->initial->fBase());
				$prunedCount++;
				$parent = dirname($dayDir);
				while (realpath($parent) !== $backupPath && count(scandir($parent)) === 2) {
					rmdir($parent);
					$parent = dirname($parent);
				}
			}
		}
		if ($prunedCount > 0) error_log(Initial::T_NAME . " | ♻️ | Pruned backups from {$prunedCount} day" . ($prunedCount > 1 ? 's' : ''));
	}
	private function validateFiles(Request $request, string $tempPath): array {
		Manager::createDirectory($tempPath);
		$tempDir = $tempPath . DIRECTORY_SEPARATOR . 'temp';
		Manager::createDirectory($tempDir);
		$files = $request->files['file'] ?? null;
		if (!is_array($files) || !isset($files['name']) || count($files['name']) !== 4) throw new Alert('Invalid data format', 400, 'b7');
		if (disk_free_space(dirname($tempPath)) < (Initial::T_SIZE * 100)) throw new Alert('Not enough disk space', 507, 'b9');
		$validated = [];
		for ($i = 0; $i < 4; $i++) {
			$filename = self::filterFile($files['name'][$i]);
			if ($files['error'][$i] !== UPLOAD_ERR_OK) throw new Alert("Upload error: {$files['error'][$i]}", 500, 'b6');
			if ($files['size'][$i] > Initial::T_SIZE) throw new Alert('File too large', 413, 'b3');
			$file = $tempDir . DIRECTORY_SEPARATOR . $filename;
			$tempFile = $files['tmp_name'][$i];
			if (!is_uploaded_file($tempFile) || !move_uploaded_file($tempFile, $file)) throw new Alert('Invalid temp file', 500, 'b6');
			if (!is_readable($file)) throw new Alert('Cannot read temp file', 500, 'b1');
			if ($filename === 'fileBase.zip') {
				if (!str_starts_with(file_get_contents($file, false, null, 0, 4), "PK\x03\x04")) throw new Alert('Invalid ZIP', 415, 'b2');
				$validated[$filename] = ['path' => $file, 'content' => null];
			} else {
				$content = file_get_contents($file);
				if (!mb_check_encoding($content, 'UTF-8')) throw new Alert('Invalid TXT', 415, 'b2');
				$validated[$filename] = ['path' => $file, 'content' => $content];
			}
		}
		return $validated;
	}
	private static function filterFile(string $filename): string {
		$name = basename($filename);
		if (!in_array($name, ['fileBase.zip', 'fileInfo.txt', 'hashList.txt', 'linkHead.txt'], true)) throw new Alert('Invalid new file: ' . $name, 400, 'b2');
		return $name;
	}
}

final class Application {
	private ?string $signatureKey = null;
	public function __construct(private Initial $initial, private Request $request, private CodesService $codesService, private LangsService $langsService, private UsersService $usersService, private UtilsService $utilsService) {}
	public function run(): void {
		if ($_SERVER['REQUEST_METHOD'] === 'GET' && !isset($_GET['status'])) {
			header('Location: /', true, 302);
			exit();
		}
		try {
			if (isset($_GET['status']) && $_GET['status'] === 'check') {
				$this->sendInfo(['status' => (disk_free_space(dirname($this->initial->rData())) > (Initial::T_SIZE * 100) && ($this->isFirst() || (is_readable($this->initial->uCase()) && is_readable($this->initial->uList())))) ? 'ok' : 'error']);
				exit();
			}
			$this->checkEnvironment();
			if ($_SERVER['REQUEST_METHOD'] === 'HEAD') {
				http_response_code(200);
				exit();
			}
			header('Cache-Control: no-store, no-cache, must-revalidate');
			if (!($this->isFirst())) $this->getClient();
			match (true) {$this->request->getPost('update') !== null => $this->handleUpdate(), $this->request->getPost('upload') !== null => $this->handleUpload(), $this->isFirst() => $this->langsService->initializeLanguages(), default => exit()};
		} catch (Alert $e) {
			$this->sendError($e->errorCode, $e->getCode(), $e->getMessage());
		} catch (Throwable $e) {
			error_log(Initial::T_NAME . ' | ⛔ | ' . sprintf("Uncaught %s: \"%s\" in %s:%d", $e::class, $e->getMessage(), $e->getFile(), $e->getLine()));
			$this->sendError('x1', 500, $e->getMessage());
		}
	}
	public static function boot(): self {
		$initial = new Initial(__DIR__);
		$request = Request::loadFrom();
		$sqlService = new SQLService();
		$codesService = new CodesService($initial, $sqlService);
		$langsService = new LangsService($initial);
		$usersService = new UsersService($initial, $sqlService);
		$utilsService = new UtilsService($initial, $sqlService, $codesService, $usersService);
		return new self($initial, $request, $codesService, $langsService, $usersService, $utilsService);
	}
	private function authenticateRequest(array $payload): array {
		$isOperator = !ctype_digit((string)($payload['i'] ?? ''));
		$userID = $isOperator ? 0 : (int)$payload['i'];
		$passwordHash = $isOperator ? Initial::O_PASS : ($this->usersService->getHash($userID) ?? throw new Alert("ID #{$userID}: not found", 404, 'a5'));
		if (!(password_verify((string)($payload['p'] ?? ''), $passwordHash)) || !(!$isOperator || password_verify((string)($payload['i'] ?? ''), Initial::O_NAME))) throw new Alert("ID #{$userID}: authentication failed", 401, 'a1');
		return ['userID' => $userID, 'isOperator' => $isOperator, 'passwordHash' => $passwordHash];
	}
	private function checkEnvironment(): void {
		if (version_compare(PHP_VERSION, '8.0.0', '<')) $this->sendError('x0', 501, 'PHP: unsupported version');
		$missing = array_filter(['ctype', 'curl', 'hash', 'json', 'mbstring', 'openssl', 'pcre', 'pdo_sqlite'], fn($ext) => !extension_loaded($ext));
		if (!empty($missing)) $this->sendError('x0', 501, 'PHP: ' . implode(', ', $missing));
		if (self::getSize(ini_get('upload_max_filesize')) < Initial::T_SIZE) $this->sendError('x0', 501, 'PHP: upload_max_filesize is too small');
		if (self::getSize(ini_get('post_max_size')) < Initial::T_SIZE) $this->sendError('x0', 501, 'PHP: post_max_size is too small');
	}
	private function getClient(): void {
		$secret = $this->usersService->getSecret();
		if ($secret === null) return;
		$token = $this->request->getPost('unbolt');
		if ($token === null || !MFAService::verifyCode($secret, (string)$token, 10, 6, MFAService::XYZ)) throw new Alert('Authentication required', 401, 'a7');
	}
	private function getKey(): ?string {
		return $this->signatureKey ??= (function(): ?string {
			$secret = $this->usersService->getSecret();
			return $secret === null ? null : hash('sha256', gmdate('Y-m-d') . $secret, true);
		})();
	}
	private function handleUpdate(): void {
		$rawPayload = (string)$this->request->getPost('update');
		$payload = $this->validatePayload($rawPayload);
		if (empty($payload['p'])) {
			$this->sendInfo((((!ctype_digit((string)($payload['i'] ?? ''))) && password_verify((string)($payload['i'] ?? ''), Initial::O_NAME)) ? 'b' : 'a') . ':' . (file_exists($this->initial->uCase()) ? '1' : '0') . (!$this->isFirst() ? '1' : '0'));
			return;
		}
		$this->verifySignature($rawPayload, Request::getHeader('X-Signature'));
		$user = $this->authenticateRequest($payload);
		$clientVersion = (int)($payload['v'] ?? 0);
		$serverVersion = $this->usersService->getVersion() ?? throw new Alert('Version not found', 404, 'a2');
		$mfaResult = ($serverVersion > 0 || (!$this->isFirst() && $user['isOperator'] && $clientVersion > -2)) ? $this->processMFA((string)$user['userID'], $user['passwordHash'], $payload['t'] ?? null, $user['isOperator'] ? (string)$payload['i'] : (string)$user['userID'], $payload['p'], $payload['h'] ?? null) : ['token' => null];
		if (isset($mfaResult['o'])) {
			$this->sendInfo($mfaResult['o']);
			return;
		}
		$newToken = $mfaResult['token'] ?? null;
		if ($newToken) $this->logAction('🔐', "ID #{$user['userID']}: token renewed");
		if ($serverVersion === $clientVersion) {
			if ($newToken) header(Initial::T_NAME . ':' . $newToken);
			$this->sendInfo('a3');
			return;
		}
		$this->logAction('✅', "ID #{$user['userID']}: update sent");
		$this->utilsService->streamFile($newToken);
	}
	private function handleUpload(): void {
		if (Initial::T_DAYS < 6) throw new Alert('Invalid backup retention period', 500, 'b8');
		$rawPayload = (string)$this->request->getPost('upload');
		Manager::initialize($this->initial);
		$payload = $this->validatePayload($rawPayload);
		$this->verifySignature($rawPayload, Request::getHeader('X-Signature'));
		$user = $this->authenticateRequest($payload);
		if (!$this->isFirst() && (is_dir($this->initial->rData()) || !file_exists($this->initial->uCase()))) {
			$mfaResult = $this->processMFA('0', Initial::O_PASS, $payload['t'] ?? null, (string)($payload['i'] ?? ''), (string)($payload['p'] ?? ''), $payload['h'] ?? null);
			if (isset($mfaResult['o'])) {
				$this->sendInfo($mfaResult['o']);
				return;
			}
			$newToken = $mfaResult['token'] ?? null;
			if ($newToken) header(Initial::T_NAME . ':' . $newToken);
		}
		if (isset($newToken) && $newToken) $this->logAction('🔐', "ID #{$user['userID']}: token renewed");
		$this->utilsService->processUpload($this->request);
		$this->langsService->checkUpdate();
		$this->logAction('☑️', "ID #{$user['userID']}: upload received");
		$this->sendInfo('a', 201);
	}
	private function isFirst(): bool {return !file_exists($this->initial->uList());}
	private function logAction(string $icon, string $message): void {error_log(Initial::T_NAME . " | {$icon} | {$message} | " . $this->request->address);}
	private function processMFA(string $userID, string $passwordHash, ?string $totpCode, ?string $userName, ?string $userCode, ?string $clientHash): array {
		$userLine = hash('sha256', $passwordHash);
		$userKey = hash_hkdf('sha256', (string)$userName . "\0" . (string)$userCode, 32, '', (string)$clientHash);
		if ($totpCode && strlen($totpCode) > 6) {
			if ($this->codesService->validateToken($totpCode, $userID, $userLine, $passwordHash, $userKey)) return ['token' => $this->codesService->createToken($userID, $userLine, $passwordHash, $userKey)];
			$this->codesService->revokeToken($userLine);
			throw new Alert("ID #{$userID}: invalid token", 401, 'q1');
		}
		$secret = MFAService::generateSecret($passwordHash . $clientHash, MFAService::ABC);
		$isValid = $totpCode && strlen($totpCode) === 6 && ctype_digit($totpCode) && MFAService::verifyCode($secret, $totpCode, 6, 30, MFAService::ABC);
		if (!$this->codesService->isReady($userLine) && !$isValid) return ['o' => 'otpauth://totp/' . Initial::T_NAME . ":{$userID}?secret={$secret}&issuer=" . Initial::T_NAME];
		if ($this->codesService->isReady($userLine) && !$isValid) {
			$this->codesService->revokeToken($userLine);
			$isEmpty = ($totpCode === null || $totpCode === '');
			throw new Alert("ID #{$userID}: " . ($isEmpty ? 'MFA entry request sent' : 'invalid token'), 401, $isEmpty ? 'q2' : 'q1');
		}
		return ['token' => $this->codesService->createToken($userID, $userLine, $passwordHash, $userKey)];
	}
	private function sendError(string $errorCode, int $httpCode, ?string $message = null): void {
		$icon = ($errorCode === 'q2') ? '🔒' : (($httpCode >= 500) ? '⛔' : '🚫');
		$this->logAction($icon, ($message ?? $errorCode) . " ({$errorCode})");
		$this->sendInfo($errorCode, $httpCode);
		exit();
	}
	private function sendInfo(string|array $data, int $httpCode = 200): void {
		http_response_code($httpCode);
		header('Content-Type: application/json; charset=UTF-8');
		if (is_string($data)) $data = ['r' => $data];
		$data['w'] = time();
		$responseBody = json_encode($data, JSON_UNESCAPED_SLASHES);
		$signatureKey = $this->getKey();
		if ($signatureKey !== null) header('X-Signature:' . base64_encode(hash_hmac('sha256', $responseBody, $signatureKey, true)));
		echo $responseBody;
	}
	private function validatePayload(?string $rawPayload): array {
		if ($rawPayload === null || strlen($rawPayload) > 600) throw new Alert('Invalid JSON', 400, 'v1');
		$payload = json_decode($rawPayload, true);
		if (!is_array($payload)) throw new Alert('Payload is not JSON', 400, 'v2');
		$userID = $payload['i'] ?? '-1';
		if (($payload['c'] ?? null) !== Initial::T_CORE) throw new Alert("ID #{$userID}: wrong version", 400, 'v3');
		if (isset($payload['p']) && (!isset($payload['w']) || !is_int($payload['w']))) throw new Alert("ID #{$userID}: invalid timestamp", 400, 'v4');
		if (isset($payload['w']) && abs(time() - $payload['w']) > 30) throw new Alert("ID #{$userID}: request has expired", 408, 'v5');
		return $payload;
	}
	private function verifySignature(string $rawPayload, ?string $clientSignature): void {
		$key = $this->getKey();
		if ($key === null) {
			if ($this->isFirst()) return;
			throw new Alert('Cannot generate signature key', 500, 's1');
		}
		if ($clientSignature === null) throw new Alert('Signature is missing', 400, 's2');
		$decodedSignature = base64_decode($clientSignature, true);
		if ($decodedSignature === false) throw new Alert('Invalid signature format', 400, 's3');
		if (!hash_equals(hash_hmac('sha256', $rawPayload, $key, true), $decodedSignature)) throw new Alert('Invalid signature', 401, 's4');
	}
	private static function getSize(string $value): int {
		$value = trim($value);
		if (!preg_match('/^(\d+)\s*([kmgtp]?)/i', $value, $matches)) return (int)$value;
		$number = (int)$matches[1];
		$unit = $matches[2] ? strtolower($matches[2]) : '';
		return match ($unit) {'p' => $number * 1024 * 1024 * 1024 * 1024 * 1024, 't' => $number * 1024 * 1024 * 1024 * 1024, 'g' => $number * 1024 * 1024 * 1024, 'm' => $number * 1024 * 1024, 'k' => $number * 1024, default => $number};
	}
}

Application::boot()->run();

?>