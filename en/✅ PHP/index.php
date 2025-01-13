<?php //@teamatica │ 0.0.0.0 │ 23.12.2017 23:59:59 UTC+00:00

$backPath = '' . DIRECTORY_SEPARATOR . 'backup' . DIRECTORY_SEPARATOR . date('Y') . DIRECTORY_SEPARATOR . date('m') . DIRECTORY_SEPARATOR . date('d') . DIRECTORY_SEPARATOR . date('H-i-s') . DIRECTORY_SEPARATOR; //backup directory
$coreInfo = 1; //current configuration version
$echoList = []; //list of all messages
$fileBase = '.txt'; //database archive
$fileInfo = '.txt'; //database version
$hashList = '.txt'; //list of authorized users
$operCode = '$2y$12$'; //ATTENTION: operator key
$operName = '$2y$12$'; //ATTENTION: operator identifier

if (empty($_POST['keys'])) { //checking for keys

	if (empty($_POST['code'])) { //checking for key
		header('Location: /'); //redirecting to main
		exit;

	} else {
		if ((password_verify($_SERVER['HTTP_USER_AGENT'], $operName)) && (password_verify($_POST['code'], $operCode))) { //checking operator data

			if (empty($_FILES)) { //checking for files
				exit('b1');

			} else {
				$countAll = count($_FILES['file']['name']); //recounting incoming files

				if ($countAll === 3) { //checking number of files
					for ($i = 0; $i < $countAll; $i++) { //starting new cycle
						$fileName = $_FILES['file']['name'][$i]; //extracting filename
						$typeInfo = pathinfo($fileName, PATHINFO_EXTENSION); //extracting file extension

						if ($typeInfo != 'txt') $echoList[] = 'b2'; //checking file extension

						if ($_FILES['file']['size'][$i] > 10000000) $echoList[] = 'b3'; //checking file size

						if (!is_writable(dirname($fileName))) $echoList[] = 'b4'; //checking write permission

						if (empty($echoList)) { //checking message count

							if (move_uploaded_file($_FILES['file']['tmp_name'][$i], basename($fileName))) { //checking move result

								if (!is_dir($backPath)) mkdir($backPath, 0700, true); //creating required path

								if (copy(basename($fileName), $backPath . basename($fileName))) { //checking backups
									chmod($backPath . basename($fileName), 0600); //hiding backups
									echo 'a';

								} else exit('b5');

								switch ($fileName) { //matching incoming files
									case 'fileBase.txt': rename($fileName, $fileBase); break; //hiding archive file
									case 'fileInfo.txt': rename($fileName, $fileInfo); break; //hiding version file
									case 'hashList.txt': rename($fileName, $hashList); break; //hiding list file
								}

							} else exit('b6');

						} else foreach ($echoList as $echo) echo $echo; //iterating through existing messages
					}

				} else exit('b7');
			}

		} else exit('b8');
	}

} else {
	list($key0, $key1, $key2, $key3) = explode('§', $_POST['keys']); //reading key set

	if ($coreInfo != $key0) exit('0'); //getting current version

	if ($key1 === $key2 && $key2 === $key3) { //comparing key set

		if (password_verify($_SERVER['HTTP_USER_AGENT'], $operName)) echo 'b'; else echo 'a'; //checking visitor role

		if (!file_exists($fileInfo)) exit('2'); //checking version existence

		if (!file_exists($hashList)) exit('4'); //checking list existence

		if (!file_exists($fileBase)) exit('6'); //checking archive existence

	} else {
		if ((($key1 == 0) && (password_verify($_SERVER['HTTP_USER_AGENT'], $operName))) || ($key1 > 0)) { //checking authorization data

			if (file_exists($fileInfo) && (filesize($fileInfo) > 0)) { //checking version existence
				$fileVers = file($fileInfo); //getting archive version

				if ($key3 != $fileVers[0]) { //comparing archive versions

					if ($key1 == 0) { //checking key value
						$hashLine = $operCode; //assigning operator key

					} else {
						if (file_exists($hashList)) { //checking list existence
							$hashText = file($hashList); //loading list content

							if (count($hashText) >= $key1 + 1) { //checking string existence
								$hashLine = trim($hashText[$key1]); //finding required string

							} else exit('a5');

						} else exit('a4');
					}

					if (password_verify($key2, $hashLine)) { //authorizing by password

						if (file_exists($fileBase)) { //checking archive existence
							header($_SERVER['SERVER_PROTOCOL'] . ' 200 OK'); //preparing archive update...
							header('Content-Type: application/zip');
							header('Content-Transfer-Encoding: binary');
							header('Content-Length: ' . filesize($fileBase));
							header('Content-Disposition: attachment; filename="teamatica.zip"');
							readfile($fileBase); //sending archive update
							exit;

						} else exit('a6');

					} else exit('a5');

				} else exit('a3');

			} else exit('a2');

		} else exit('a1');
	}
}

?>