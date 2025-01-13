<?php //@teamatica │ 0.0.0.0 │ 23.12.2017 23:59:59 UTC+00:00

$backPath = '' . DIRECTORY_SEPARATOR . 'backup' . DIRECTORY_SEPARATOR . date('Y') . DIRECTORY_SEPARATOR . date('m') . DIRECTORY_SEPARATOR . date('d') . DIRECTORY_SEPARATOR . date('H-i-s') . DIRECTORY_SEPARATOR; //каталог резервного копіювання
$coreInfo = 1; //поточна версія конфігурації
$echoList = []; //список всіх повідомлень
$fileBase = '.txt'; //архів бази даних
$fileInfo = '.txt'; //версія бази даних
$hashList = '.txt'; //список авторизованих користувачів
$operCode = '$2y$12$'; //УВАГА: ключ оператора
$operName = '$2y$12$'; //УВАГА: ідентифікатор оператора

if (empty($_POST['keys'])) { //перевіряємо наявність ключів

	if (empty($_POST['code'])) { //перевіряємо наявність ключа
		header('Location: /'); //відправляємо на головну
		exit;

	} else {
		if ((password_verify($_SERVER['HTTP_USER_AGENT'], $operName)) && (password_verify($_POST['code'], $operCode))) { //перевіряємо дані оператора

			if (empty($_FILES)) { //перевіряємо наявність файлів
				exit('b1');

			} else {
				$countAll = count($_FILES['file']['name']); //перераховуємо вхідні файли

				if ($countAll === 3) { //перевіряємо кількість файлів
					for ($i = 0; $i < $countAll; $i++) { //запускаємо новий цикл
						$fileName = $_FILES['file']['name'][$i]; //витягуємо ім'я файлу
						$typeInfo = pathinfo($fileName, PATHINFO_EXTENSION); //витягуємо розширення файлу

						if ($typeInfo != 'txt') $echoList[] = 'b2'; //перевіряємо розширення файлу

						if ($_FILES['file']['size'][$i] > 10000000) $echoList[] = 'b3'; //перевіряємо розмір файлу

						if (!is_writable(dirname($fileName))) $echoList[] = 'b4'; //перевіряємо можливість запису

						if (empty($echoList)) { //перевіряємо кількість повідомлень

							if (move_uploaded_file($_FILES['file']['tmp_name'][$i], basename($fileName))) { //перевіряємо результат переміщення

								if (!is_dir($backPath)) mkdir($backPath, 0700, true); //створюємо необхідний шлях

								if (copy(basename($fileName), $backPath . basename($fileName))) { //перевіряємо резервні копії
									chmod($backPath . basename($fileName), 0600); //ховаємо резервні копії
									echo 'a';

								} else exit('b5');

								switch ($fileName) { //зіставляємо вхідні файли
									case 'fileBase.txt': rename($fileName, $fileBase); break; //ховаємо файл архіву
									case 'fileInfo.txt': rename($fileName, $fileInfo); break; //ховаємо файл версії
									case 'hashList.txt': rename($fileName, $hashList); break; //ховаємо файл списку
								}

							} else exit('b6');

						} else foreach ($echoList as $echo) echo $echo; //перебираємо наявні повідомлення
					}

				} else exit('b7');
			}

		} else exit('b8');
	}

} else {
	list($key0, $key1, $key2, $key3) = explode('§', $_POST['keys']); //зчитуємо набір ключів

	if ($coreInfo != $key0) exit('0'); //дізнаємось поточну версію

	if ($key1 === $key2 && $key2 === $key3) { //порівнюємо набір ключів

		if (password_verify($_SERVER['HTTP_USER_AGENT'], $operName)) echo 'b'; else echo 'a'; //перевіряємо роль відвідувача

		if (!file_exists($fileInfo)) exit('2'); //перевіряємо наявність версії

		if (!file_exists($hashList)) exit('4'); //перевіряємо наявність списку

		if (!file_exists($fileBase)) exit('6'); //перевіряємо наявність архіву

	} else {
		if ((($key1 == 0) && (password_verify($_SERVER['HTTP_USER_AGENT'], $operName))) || ($key1 > 0)) { //перевіряємо дані авторизації

			if (file_exists($fileInfo) && (filesize($fileInfo) > 0)) { //перевіряємо наявність версії
				$fileVers = file($fileInfo); //дізнаємось версію архіву

				if ($key3 != $fileVers[0]) { //порівнюємо версії архівів

					if ($key1 == 0) { //перевіряємо значення ключа
						$hashLine = $operCode; //присвоюємо ключ оператора

					} else {
						if (file_exists($hashList)) { //перевіряємо наявність списку
							$hashText = file($hashList); //завантажуємо вміст списку

							if (count($hashText) >= $key1 + 1) { //перевіряємо наявність рядка
								$hashLine = trim($hashText[$key1]); //знаходимо потрібний рядок

							} else exit('a5');

						} else exit('a4');
					}

					if (password_verify($key2, $hashLine)) { //авторизуємо за паролем

						if (file_exists($fileBase)) { //перевіряємо наявність архіву
							header($_SERVER['SERVER_PROTOCOL'] . ' 200 OK'); //готуємо оновлення архіву...
							header('Content-Type: application/zip');
							header('Content-Transfer-Encoding: binary');
							header('Content-Length: ' . filesize($fileBase));
							header('Content-Disposition: attachment; filename="teamatica.zip"');
							readfile($fileBase); //відправляємо оновлення архіву
							exit;

						} else exit('a6');

					} else exit('a5');

				} else exit('a3');

			} else exit('a2');

		} else exit('a1');
	}
}

?>