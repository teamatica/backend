<?php //@teamatica │ 0.0.0.0 │ 23.12.2017 23:59:59 UTC+00:00

$backPath = '' . DIRECTORY_SEPARATOR . 'backup' . DIRECTORY_SEPARATOR . date('Y') . DIRECTORY_SEPARATOR . date('m') . DIRECTORY_SEPARATOR . date('d') . DIRECTORY_SEPARATOR . date('H-i-s') . DIRECTORY_SEPARATOR; //сақтық көшірме каталогы
$coreInfo = 2; //конфигурацияның ағымдағы нұсқасы
$echoList = []; //барлық хабарламалар тізімі
$fileBase = '.txt'; //дерекқор мұрағаты
$fileInfo = '.txt'; //дерекқор нұсқасы
$hashList = '.txt'; //авторизацияланған пайдаланушылар тізімі
$operCode = '$2y$12$'; //НАЗАР АУДАРЫҢЫЗ: оператор кілті
$operName = '$2y$12$'; //НАЗАР АУДАРЫҢЫЗ: оператор идентификаторы

if (empty($_POST['keys'])) { //кілттердің бар-жоғын тексереміз

	if (empty($_POST['code'])) { //кілттің бар-жоғын тексереміз
		header('Location: /'); //басты бетке жібереміз
		exit;

	} else {
		list($key0, $key1) = explode('§', $_POST['code']); //кілттер жиынтығын оқимыз

		if ($coreInfo != $key0) exit('0'); //ағымдағы нұсқаны анықтаймыз

		if ((password_verify($_SERVER['HTTP_USER_AGENT'], $operName)) && (password_verify($key1, $operCode))) { //оператор деректерін тексереміз

			if (empty($_FILES)) { //файлдардың бар-жоғын тексереміз
				exit('b1');

			} else {
				$countAll = count($_FILES['file']['name']); //кіріс файлдарын қайта санаймыз

				if ($countAll === 3) { //файлдар санын тексереміз
					for ($i = 0; $i < $countAll; $i++) { //жаңа циклды бастаймыз
						$fileName = $_FILES['file']['name'][$i]; //файл атауын шығарамыз
						$typeInfo = pathinfo($fileName, PATHINFO_EXTENSION); //файл кеңейтімін шығарамыз

						if ($typeInfo != 'txt') $echoList[] = 'b2'; //файл кеңейтімін тексереміз

						if ($_FILES['file']['size'][$i] > 10000000) $echoList[] = 'b3'; //файл өлшемін тексереміз

						if (!is_writable(dirname($fileName))) $echoList[] = 'b4'; //жазу мүмкіндігін тексереміз

						if (empty($echoList)) { //хабарламалар санын тексереміз

							if (move_uploaded_file($_FILES['file']['tmp_name'][$i], basename($fileName))) { //жылжыту нәтижесін тексереміз

								if (!is_dir($backPath)) mkdir($backPath, 0700, true); //қажетті жолды құрамыз

								if (copy(basename($fileName), $backPath . basename($fileName))) { //сақтық көшірмелерді тексереміз
									chmod($backPath . basename($fileName), 0600); //сақтық көшірмелерді жасырамыз
									echo 'a';

								} else exit('b5');

								switch ($fileName) { //кіріс файлдарын салыстырамыз
									case 'fileBase.txt': rename($fileName, $fileBase); break; //мұрағат файлын жасырамыз
									case 'fileInfo.txt': rename($fileName, $fileInfo); break; //нұсқа файлын жасырамыз
									case 'hashList.txt': rename($fileName, $hashList); break; //тізім файлын жасырамыз
								}

							} else exit('b6');

						} else foreach ($echoList as $echo) echo $echo; //бар хабарламаларды қарастырамыз
					}

				} else exit('b7');
			}

		} else exit('b8');
	}

} else {
	list($key0, $key1, $key2, $key3) = explode('§', $_POST['keys']); //кілттер жиынтығын оқимыз

	if ($coreInfo != $key0) exit('0'); //ағымдағы нұсқаны анықтаймыз

	if ($key1 === $key2 && $key2 === $key3) { //кілттер жиынтығын салыстырамыз

		if (password_verify($_SERVER['HTTP_USER_AGENT'], $operName)) echo 'b'; else echo 'a'; //қонақтың рөлін тексереміз

		if (!file_exists($fileInfo)) exit('2'); //нұсқаның бар-жоғын тексереміз

		if (!file_exists($hashList)) exit('4'); //тізімнің бар-жоғын тексереміз

		if (!file_exists($fileBase)) exit('6'); //мұрағаттың бар-жоғын тексереміз

	} else {
		if ((($key1 == 0) && (password_verify($_SERVER['HTTP_USER_AGENT'], $operName))) || ($key1 > 0)) { //авторизация деректерін тексереміз

			if (file_exists($fileInfo) && (filesize($fileInfo) > 0)) { //нұсқаның бар-жоғын тексереміз
				$fileVers = file($fileInfo); //мұрағат нұсқасын анықтаймыз

				if ($key3 != $fileVers[0]) { //мұрағат нұсқаларын салыстырамыз

					if ($key1 == 0) { //кілт мәнін тексереміз
						$hashLine = $operCode; //оператор кілтін тағайындаймыз

					} else {
						if (file_exists($hashList)) { //тізімнің бар-жоғын тексереміз
							$hashText = file($hashList); //тізім мазмұнын жүктейміз

							if (count($hashText) >= $key1 + 1) { //жолдың бар-жоғын тексереміз
								$hashLine = trim($hashText[$key1]); //қажетті жолды табамыз

							} else exit('a5');

						} else exit('a4');
					}

					if (password_verify($key2, $hashLine)) { //құпия сөз арқылы авторизациялаймыз

						if (file_exists($fileBase)) { //мұрағаттың бар-жоғын тексереміз
							header($_SERVER['SERVER_PROTOCOL'] . ' 200 OK'); //мұрағат жаңартуын дайындаймыз...
							header('Content-Type: application/zip');
							header('Content-Transfer-Encoding: binary');
							header('Content-Length: ' . filesize($fileBase));
							header('Content-Disposition: attachment; filename="teamatica.zip"');
							readfile($fileBase); //мұрағат жаңартуын жібереміз
							exit;

						} else exit('a6');

					} else exit('a5');

				} else exit('a3');

			} else exit('a2');

		} else exit('a1');
	}
}

?>