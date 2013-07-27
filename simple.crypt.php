<?php
define("CLI", !isset($_SERVER['HTTP_USER_AGENT']));

if(CLI) {
	$register = new SimpleEncrypt($argv);
	$register->generate();
}

class SimpleEncrypt{

	private $_encrypted = NULL;
	private $_data 		= NULL;
 	private $_salt 		= '6[EDWE@&l99#Knw';
	
	public function __construct($argv = array())
	{
		try{
			if(!file_exists('Crypt/AES.php')){
				throw new Exception('Cannot load default library user');
 			}else{
				require_once('Crypt/AES.php');
			}
			
			if(count($argv)!=2){
				throw new Exception("Error > Usage: php ".$argv[0]." <user> <pass>\n");
 			}else{
				$this->_data=$argv[1];
 			}
 
		}catch (Exception $e){
            echo "<pre>";
			var_dump($e);
			echo "</pre>";
			exit(1);
 		}
 	}
	
	public function generate()
	{
		try{
			$this->_encrypted 	= false;
 
			$key=hash('md5',$this->_data);
			$aes = new Crypt_AES();
			$aes->setKeyLength(256);
			$aes->setKey($key);
			
			$this->_data		= $aes->encrypt($this->_data);
 			$this->_data 		= base64_encode($this->_data);
 			
 			$this->_encrypted 	= true;
			
			$stdout = fopen('php://stdout', 'w');
			fwrite($stdout,$this->_data);
			
		}catch (Exception $e){
			echo "<pre>";
			var_dump($e);
			echo "</pre>";
			exit(1);
 		}
	}
}
?>