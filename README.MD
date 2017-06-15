# VinkDownloader #
---
Use your server to download file faster

## Getting started

- edit main.go
  ```go
  var (
  	process_ = "424314ljkaFAFaf"
  	monkey = "AES256Key-32fsd#$!@"
	conf_url = "https://share.cdn.wenqi.us/ex/sl.apo"
  )
  //monkey replace as your aes-256-cfb key
  //process_ replace as your key's offset
  //conf_url replace as your conf file form network
  ```

- edit you conf(all value show be encrypt)
  ```json
  {
      "key1": "3a95327bd4da3e",   //server ip or host
      "key2": "b7bp4da3e9b7",     //password
      "key3": "Zq42#21",          //username   
      "key4": "$#l1A"             //ssh port
  }
  //all value show be encrypt
  ```
  
- go build 

- run  (-d will delete server file )   
  `./vinkDownloader http://jsptest.sourceforge.net/maven2/net/sf/jsptest/jsptest-acceptance-jsp12/0.11/jsptest-acceptance-jsp12-0.11-sources.jar -d`
  
