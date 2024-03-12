<?php
define("FROM_PHP",1);

try {
	require_once("_cvaultsentinel.php");

	cvault_init();

	$count = 10000;

	$start = microtime(true);
	for ($i = 0; $i < $count; $i++) {
		$data = "test_encryption_data".$i;

		$encrypted = cvault_encrypt($data);
		if (!$encrypted) throw new Exception($cvault_lasterror);

		$decrypted = cvault_decrypt($encrypted);
		if (!$decrypted) throw new Exception($cvault_lasterror);

		if ($data != $decrypted) throw new Exception("Fail operation ".$data." != ".$decrypted);
	}
	$end = microtime(true);

	printf("Time spend for %d ops: %.2f (%.2f rps)\n",
		$count, $end - $start, $count / ($end - $start));


	$start = microtime(true);
	for ($i = 0; $i < $count; $i++) {
		$data = "test_encryption_data".$i;

		$encrypted = cvault_encrypt($data,true);
		if (!$encrypted) throw new Exception($cvault_lasterror);

		$decrypted = cvault_decrypt($encrypted);
		if (!$decrypted) throw new Exception($cvault_lasterror);

		if ($data != $decrypted) throw new Exception("Fail operation ".$data." != ".$decrypted);
	}
	$end = microtime(true);

	printf("Time spend for %d ops with checking: %.2f (%.2f rps)\n",
		$count, $end - $start, $count / ($end - $start));

	cvault_deinit();

} catch (Exception $e) {
	echo "Exception: ",$e->getMessage();
} // catch
