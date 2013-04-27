#!/usr/bin/php
<?php

class Scanner {
	const S_IFDIR = 0040000;
	
	public function scan($path) {
		foreach (scandir($path) as $file) {
			if (substr($file, 0, 1) == '.') continue;
			$rfile = "{$path}/{$file}";
			$rfileStat = @stat($rfile);
			if ($rfileStat === false) continue;
			$rfileStat = (object)$rfileStat;
			$rfileInfo = (object)pathinfo($rfile);
			
			if ($rfileStat->mode & Scanner::S_IFDIR) {
				$this->scan($rfile);
			} else {
				if ($rfileStat->size < 256 * 1024) {
					$rfileContent = file_get_contents($rfile);
					// It is a PHP file
					if (strpos($rfileContent, '<'.'?php') !== false) {
						$suspicious = 0;
						$warns = array();

						// Detect some suspicious functions
						if (preg_match_all('@(mkdir|fopen|fclose|readfile)@i', $rfileContent, $matches)) {
							$suspicious += 1;
							foreach ($matches[0] as $match) $warns[] = $match;
						}

						// Detect some suspicious functions
						if (preg_match_all('@(eval|passthru|shell_exec|system|phpinfo|base64_decode|chmod|create_function)@i', $rfileContent, $matches)) {
							$matchCount = count($matches[0]);
							foreach ($matches[0] as $match) $warns[] = $match;
							$suspicious += $matchCount;
						}

						// Detect dynamic function call
						if (preg_match('@\$\w+\s*\(@i', $rfileContent)) {
							$warns[] = '$dynamic_execution()';
							$suspicious += 10;
						}
						
						// Unexpected extension
						if (!in_array($rfileInfo->extension, array('php', 'inc'))) {
							$suspicious += 10;
							$warns[] = '$unexpected_extension(' . $rfileInfo->extension . ')';
						}
						
						$warns = array_unique($warns);

						if ($suspicious > 0) {
							echo realpath($rfile) . "... WarningLevel: {$suspicious} [" . implode(',', $warns) . "]\n";
						}
					}
				}
			}
		}
	}
}

if (count($argv) < 2) {
	die("scan.php <path>");
} else {
	$scanner = new Scanner();
	$scanner->scan($argv[1]);
}
