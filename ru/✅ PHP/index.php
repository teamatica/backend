<?php //@teamatica │ 0.0.0.0 │ 23.12.2017 23:59:59 UTC+00:00

$backPath = '' . DIRECTORY_SEPARATOR . 'backup' . DIRECTORY_SEPARATOR . date('Y') . DIRECTORY_SEPARATOR . date('m') . DIRECTORY_SEPARATOR . date('d') . DIRECTORY_SEPARATOR . date('H-i-s') . DIRECTORY_SEPARATOR; //каталог резервного копирования
$coreInfo = 1; //текущая версия конфигурации
$echoList = []; //список всех сообщений
$fileBase = '.txt'; //архив базы данных
$fileInfo = '.txt'; //версия базы данных
$hashList = '.txt'; //список авторизованных пользователей
$operCode = '$2y$12$'; //ВНИМАНИЕ: ключ оператора
$operName = '$2y$12$'; //ВНИМАНИЕ: идентификатор оператора

if (empty($_POST['keys'])) { //проверяем наличие ключей

	if (empty($_POST['code'])) { //проверяем наличие ключа
		header('Location: /'); //отправляем на главную
		exit;

	} else {
		if ((password_verify($_SERVER['HTTP_USER_AGENT'], $operName)) && (password_verify($_POST['code'], $operCode))) { //проверяем данные оператора

			if (empty($_FILES)) { //проверяем наличие файлов
				exit('b1');

			} else {
				$countAll = count($_FILES['file']['name']); //пересчитываем входящие файлы

				if ($countAll === 3) { //проверяем количество файлов
					for ($i = 0; $i < $countAll; $i++) { //запускаем новый цикл
						$fileName = $_FILES['file']['name'][$i]; //вытаскиваем имя файла
						$typeInfo = pathinfo($fileName, PATHINFO_EXTENSION); //вытаскиваем расширение файла

						if ($typeInfo != 'txt') $echoList[] = 'b2'; //проверяем расширение файла

						if ($_FILES['file']['size'][$i] > 10000000) $echoList[] = 'b3'; //проверяем размер файла

						if (!is_writable(dirname($fileName))) $echoList[] = 'b4'; //проверяем возможность записи

						if (empty($echoList)) { //проверяем количество сообщений

							if (move_uploaded_file($_FILES['file']['tmp_name'][$i], basename($fileName))) { //проверяем результат перемещения

								if (!is_dir($backPath)) mkdir($backPath, 0700, true); //создаём необходимый путь

								if (copy(basename($fileName), $backPath . basename($fileName))) { //проверяем резервные копии
									chmod($backPath . basename($fileName), 0600); //прячем резервные копии
									echo 'a';

								} else exit('b5');

								switch ($fileName) { //сопоставляем входящие файлы
									case 'fileBase.txt': rename($fileName, $fileBase); break; //прячем файл архива
									case 'fileInfo.txt': rename($fileName, $fileInfo); break; //прячем файл версии
									case 'hashList.txt': rename($fileName, $hashList); break; //прячем файл списка
								}

							} else exit('b6');

						} else foreach ($echoList as $echo) echo $echo; //перебираем имеющиеся сообщения
					}

				} else exit('b7');
			}

		} else exit('b8');
	}

} else {
	list($key0, $key1, $key2, $key3) = explode('§', $_POST['keys']); //считываем набор ключей

	if ($coreInfo != $key0) exit('0'); //узнаём текущую версию

	if ($key1 === $key2 && $key2 === $key3) { //сравниваем набор ключей

		if (password_verify($_SERVER['HTTP_USER_AGENT'], $operName)) echo 'b'; else echo 'a'; //проверяем роль посетителя

		if (!file_exists($fileInfo)) exit('2'); //проверяем наличие версии

		if (!file_exists($hashList)) exit('4'); //проверяем наличие списка

		if (!file_exists($fileBase)) exit('6'); //проверяем наличие архива

	} else {
		if ((($key1 == 0) && (password_verify($_SERVER['HTTP_USER_AGENT'], $operName))) || ($key1 > 0)) { //проверяем данные авторизации

			if (file_exists($fileInfo) && (filesize($fileInfo) > 0)) { //проверяем наличие версии
				$fileVers = file($fileInfo); //узнаём версию архива

				if ($key3 != $fileVers[0]) { //сравниваем версии архивов

					if ($key1 == 0) { //проверяем значение ключа
						$hashLine = $operCode; //присваиваем ключ оператора

					} else {
						if (file_exists($hashList)) { //проверяем наличие списка
							$hashText = file($hashList); //загружаем содержимое списка

							if (count($hashText) >= $key1 + 1) { //проверяем наличие строки
								$hashLine = trim($hashText[$key1]); //находим нужную строку

							} else exit('a5');

						} else exit('a4');
					}

					if (password_verify($key2, $hashLine)) { //авторизуем по паролю

						if (file_exists($fileBase)) { //проверяем наличие архива
							header($_SERVER['SERVER_PROTOCOL'] . ' 200 OK'); //готовим обновление архива...
							header('Content-Type: application/zip');
							header('Content-Transfer-Encoding: binary');
							header('Content-Length: ' . filesize($fileBase));
							header('Content-Disposition: attachment; filename="teamatica.zip"');
							readfile($fileBase); //отправляем обновление архива
							exit;

						} else exit('a6');

					} else exit('a5');

				} else exit('a3');

			} else exit('a2');

		} else exit('a1');
	}
}

?>