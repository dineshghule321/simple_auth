<?php
define("CLI", !isset($_SERVER['HTTP_USER_AGENT']));

//$auth = new AuthUsers();
//var_dump($auth->authenticate("admin","ROQjxPg#Tcs-K6sO"));
	 
class AuthUsers{
 
	private $_encrypted = NULL;
	private $_user 		= NULL;
	private $_pass 		= NULL;
	private $_salt 		= '6[EDWE@&l99#Knw';

	public function __construct()
	{
		try{
			if(!file_exists('Crypt/AES.php')){
				throw new Exception('Cannot load default library AES');
 			}else{
				require_once('Crypt/AES.php');
			}
	
			define('DB_DSN',"mysql:host=localhost;dbname=".'DB_NAME_GOES_HERE');
			define('DB_USERNAME','root');
			define('DB_PASSWORD','');
 
		}catch (Exception $e){
            error_log($e);
  		}
 	}
	
	public function authenticate($user = null, $pass = null)
	{
 		try{
			$this->_encrypted 	= false;
			
			if(!isset($user) || !isset($pass)) {
				throw new Exception('No user or pass to authenticate');
			}
			
			$key=hash('md5',$pass.$this->_salt.$user);
			$aes = new Crypt_AES();
			$aes->setKeyLength(256);
			$aes->setKey($key);
			
			$user		= $aes->encrypt($user);
			$pass 		= $aes->encrypt($pass);
			
			$this->_user 		= base64_encode($user);
			$this->_pass 		= base64_encode($pass);
			
 			$this->_encrypted 	= true;
			return $this->auth_to_bd();
			
		}catch (Exception $e){
            error_log($e);
			return false;
 		}
 	}
	
	private function auth_to_bd()
	{
		try{
			if(!isset($this->_encrypted) || !$this->_encrypted){
				throw new Exception('No user or pass to authenticate');
			}
 
			$query= "select count(*) as yes from `admins` where `username` = :XXX_USER_XXX and `password` = :XXX_PASS_XXX";
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
			
			$return = $this->openDB($query,$special_values, true); 
			if(isset($return['status']) && $return['status']!==false){
				
				if(isset($return['results'][0]['yes']) && $return['results'][0]['yes'] === "1"){
					return true;;
				}
 			}
 		}catch (Exception $e){
            error_log($e);
  		}
		
		return false;
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
  		}
	}
}

?>