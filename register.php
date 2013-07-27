<?php

define("CLI", !isset($_SERVER['HTTP_USER_AGENT']));

if(CLI) {
	$register = new RegisterUserEnc($argv);
	$register->save_to_db();
}

class RegisterUserEnc{

	private $_encrypted = NULL;
	private $_user 		= NULL;
	private $_pass 		= NULL;
	private $_salt 		= '6[EDWE@&l99#Knw';
	
	public function __construct($argv = array())
	{
		try{
			if(!file_exists('Crypt/AES.php')){
				throw new Exception('Cannot load default library AES');
 			}else{
				require_once('Crypt/AES.php');
			}
			
			if(count($argv)!=3){
				throw new Exception("Error > Usage: php ".$argv[0]." <user> <pass>\n");
 			}else{
				$this->_user=$argv[1];
				$this->_pass=$argv[2];
			}
			
			define('DB_DSN',"mysql:host=localhost;dbname=".'DB_NAME_GOES_HERE');
			define('DB_USERNAME','root');
			define('DB_PASSWORD','');
			
		}catch (Exception $e){
            error_log($e);
			exit(1);
 		}
 	}
	
	public function generateUserPassCrypt()
	{
		try{
			$this->_encrypted 	= false;
 
			$key=hash('md5',$this->_pass.$this->_salt.$this->_user);
			$aes = new Crypt_AES();
			$aes->setKeyLength(256);
			$aes->setKey($key);
			
			$this->_user		= $aes->encrypt($this->_user);
			$this->_pass 		= $aes->encrypt($this->_pass);
			
			$this->_user 		= base64_encode($this->_user);
			$this->_pass 		= base64_encode($this->_pass);
			
 			$this->_encrypted 	= true;
			
		}catch (Exception $e){
            error_log($e);
			exit(1);
 		}
	}
	
	public function save_to_db()
	{
		try{
			if(!isset($this->_encrypted) || !$this->_encrypted){
				$this->generateUserPassCrypt();
			}
 
			$query= "INSERT INTO `admins` (`username`, `password`) VALUES (:XXX_USER_XXX, :XXX_PASS_XXX)";
			$special_values=array(
				array(
					'key' => "XXX_USER_XXX",
					'value' => $this->_user,
					'kind' => PDO::PARAM_STR
					),
				array(
					'key' => "XXX_PASS_XXX",
					'value' => $this->_pass,
					'kind' => PDO::PARAM_STR
				)
			);
			$return = $this->openDB($query,$special_values); 
			if(isset($return['status']) && $return['status']!==false){
				exit(0);
			}else{
				exit(1);
			}
		}catch (Exception $e){
            error_log($e);
			exit(1);
 		}

	}
	
	private function openDB($query,$special_values=null,$results=null){
		try {
 			$pdoLayer = new PDO( DB_DSN, DB_USERNAME, DB_PASSWORD );	
			$queryClone=$query;
 			$return_values = array(
				"status" => null,
				"results" => null
			);
			/* 
			* Lets bind those special values here!
			* Why bind and not quote? 
			* Security and efficiency, check: http://php.net/manual/en/pdo.quote.php
			*/
			$preparedStatement=$pdoLayer->prepare($queryClone);
			
			if(isset($special_values)){
				foreach($special_values as $item){
					$preparedStatement->bindParam($item['key'], $item['value'], $item['kind']);
				}
			}

			$res=$preparedStatement->execute();
			if(isset($results)){
				$returnedRows=$preparedStatement->fetchAll();
				$return_values['results'] = $returnedRows;
			}
			
			$return_values['status'] = $res;
			
			/* clean memory */
			$pdoLayer=null;
 			return $return_values;			
			
		}catch (Exception $e){
            error_log($e);
			exit(1);
 		}
	}
}
?>