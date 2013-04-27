#!/usr/bin/php
<?php

class Scanner {
	const S_IFDIR = 0040000;
	
	public $minWarningLevel = 1;
	private $scannerContent;
	
	public function __construct() {
		$this->scannerContent = file_get_contents(__FILE__);
	}
	
	public function scan($path) {
		foreach (scandir($path) as $file) {
			if (substr($file, 0, 1) == '.') continue;
			$rfile = "{$path}/{$file}";
			$rfileStat = @stat($rfile);
			if ($rfileStat === false) continue;
			$rfileStat = (object)$rfileStat;
			$rfileInfo = (object)pathinfo($rfile);
			if (!isset($rfileInfo->extension)) $rfileInfo->extension = '';
			
			if ($rfileStat->mode & Scanner::S_IFDIR) {
				$this->scan($rfile);
			} else {
				if ($rfileStat->size < 256 * 1024) {
					$rfileContent = file_get_contents($rfile);
					// It is a PHP file
					if (strpos($rfileContent, '<'.'?php') !== false) {
						$rfile = realpath($rfile);
						
						// Ignore self.
						if ($rfile == __FILE__) continue;
						if ($rfileContent == $this->scannerContent) continue;
					
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

						// Well Known Backdoor Keywords
						if (preg_match_all('@(WSO_VERSION)@', $rfileContent, $matches)) {
							$warns[] = '$web_shell';
							$suspicious += 1000;
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

						if ($suspicious >= $this->minWarningLevel) {
							echo $rfile . "... WarningLevel: {$suspicious} [" . implode(',', $warns) . "]\n";
						}
					}
				}
			}
		}
	}
}

class CommandLineProgramParser {
	public $params = array();
	public $title = '';
	public $parseOptions = array();
	
	public function __construct() {
	}
	
	public function showHelp() {
		echo "{$this->title}\n";
		echo "\n";
		echo "OPTIONS:\n";
		foreach ($this->parseOptions as $key => $info) {
			list($name, $default) = $info;
			echo "  --{$name}=<value> | default = {$default}\n";
		}
		echo "\n";
		echo "scan.php <path>\n";
		echo "\n";
		exit;
	}
	
	public function addOption($name, $defaultValue) {
		$this->parseOptions[strtolower($name)] = array($name, $defaultValue);
	}
	
	public function parse($argv) {
		array_shift($argv);
		$params = array();
		$extra = array();
		for ($n = 0; $n < count($argv); $n++) {
			$arg = $argv[$n];
			if (substr($arg, 0, 1) == '-') {
				$value = false;
				if (strpos($arg, '=') !== false) {
					list($arg, $value) = explode('=', ltrim($arg, '-'), 2);
				} else {
					@$value = $argv[++$n];
				}
				if (!isset($this->parseOptions[strtolower($arg)])) {
					throw(new Exception("Unknown option '{$arg}'"));
				}
				$params[strtolower($arg)] = $value;
				//echo "$arg: $value\n";
			} else {
				$extra[] = $arg;
			}
		}
		return (object)array(
			'params' => (object)$params,
			'extra' => $extra,
		);
	}
}

$commandLineProgramParser = new CommandLineProgramParser();
$commandLineProgramParser->title = 'PHP Backdoor Scanner - soywiz - 2013';
$commandLineProgramParser->addOption('minWarningLevel', 0);
$info = $commandLineProgramParser->parse($argv);

if (count($info->extra) == 0) {
	$commandLineProgramParser->showHelp();
} else {
	$scanner = new Scanner();
	$scanner->minWarningLevel = isset($info->params->minwarninglevel) ? $info->params->minwarninglevel : 1;
	$scanner->scan($info->extra[0]);
}
