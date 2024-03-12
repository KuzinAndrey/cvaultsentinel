<?php
if (!defined("FROM_PHP")) die("Can't call this file");

require_once(dirname(__FILE__)."/_config.php");

$cvault_handler = NULL;
$cvault_lasterror = NULL;

function cvault_init() {
	global $cvault_handler;
	global $config;

	$cvault_handler = curl_init();

	curl_setopt($cvault_handler, CURLOPT_USERAGENT, "some_user_agent");
	// curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false); // не проверять SSL сертификат на валидность
	curl_setopt($cvault_handler, CURLOPT_TIMEOUT, 2); //
	curl_setopt($cvault_handler, CURLOPT_RETURNTRANSFER, true); //
	curl_setopt($cvault_handler, CURLOPT_HTTPHEADER, array(
		"PRIVATE-TOKEN: ".$config["cvault_api_token"], // TODO not implemented yet
		)
	);

	// curl_setopt($curl, CURLOPT_HEADER, 1); // Получаем ответ сервера с заголовками
	// curl_setopt($curl, CURLOPT_COOKIEFILE, ""); // храним куки сессии в памяти
	// if (defined('DEBUG')) curl_setopt($cvault_handler, CURLOPT_VERBOSE, true);
	curl_setopt($cvault_handler, CURLOPT_POST, 1);
} // cvault_init()

function cvault_deinit() {
	global $cvault_handler;
	global $cvault_lasterror;
	if ($cvault_handler != NULL) {
		curl_close($cvault_handler);
		$cvault_handler = NULL;
		$cvault_lasterror = NULL;
	}
} // cvault_deinit

function cvault_encrypt($data, $check = false) {
	global $cvault_handler;
	global $cvault_lasterror;
	global $config;

	if ($cvault_handler == NULL) cvault_init();
	if (!$cvault_handler) {
		$cvault_lasterror = "Can't init curl";
		return NULL;
	}

	$try = 0;
	while ($try < 10) {
		$try++;

		try {
			curl_setopt($cvault_handler, CURLOPT_URL, $config["cvault_api"]."/encrypt");
			curl_setopt($cvault_handler, CURLOPT_POSTFIELDS, $data);
			curl_setopt($cvault_handler, CURLOPT_TIMEOUT, 10);

			// Try to crypt
			$crypted = curl_exec($cvault_handler);
			if ($errno = curl_errno($cvault_handler))
				throw new Exception("Curl error ".$errno." - ".curl_strerror($errno));
		
			$code = curl_getinfo($cvault_handler, CURLINFO_HTTP_CODE);
			if (200 != $code)
				throw new Exception("HTTP code ".$code." from crypt API");

			if ($check) {
				// Try to decrypt
				curl_setopt($cvault_handler, CURLOPT_URL, $config["cvault_api"]."/decrypt");
				curl_setopt($cvault_handler, CURLOPT_POSTFIELDS, $crypted);

				$decrypted = curl_exec($cvault_handler);
				if ($errno = curl_errno($cvault_handler))
					throw new Exception("Curl error ".$errno." - ".curl_strerror($errno));

				$code = curl_getinfo($cvault_handler, CURLINFO_HTTP_CODE);
				if (200 != $code)
					throw new Exception("HTTP code ".$code." from decrypt API");

				// Check data
				if ($decrypted != $data)
					throw new Exception("Decrypted data not equal to original");
			}

			return $crypted;
		} catch (Exception $e) {
			$cvault_lasterror = $e->getMessage();
			continue;
		}
	} // while

	return NULL;
} // cvault_encrypt()

function cvault_decrypt($data) {
	global $cvault_handler;
	global $cvault_lasterror;
	global $config;

	if ($cvault_handler == NULL) cvault_init();
	if (!$cvault_handler) {
		$cvault_lasterror = "Can't init curl";
		return NULL;
	}

	curl_setopt($cvault_handler, CURLOPT_URL, $config["cvault_api"]."/decrypt");
	curl_setopt($cvault_handler, CURLOPT_POSTFIELDS, $data);

	$rez = curl_exec($cvault_handler);
	if ($errno = curl_errno($cvault_handler)) {
		$cvault_lasterror = $errno." - ".curl_strerror($errno);
		return NULL;
	}

	$code = curl_getinfo($cvault_handler, CURLINFO_HTTP_CODE);
	if (200 != $code) {
		$cvault_lasterror = "Code ".$code." from API";
		return NULL;
	};

	return $rez;
} // cvault_decrypt()
