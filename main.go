package main

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"log"
	"time"
	"fmt"
	"net"
	"bytes"
	"github.com/pkg/sftp"
	"strings"
	"github.com/bitly/go-simplejson"
	"net/http"
	"io/ioutil"
	"strconv"
	"encoding/hex"
	"crypto/aes"
	"crypto/cipher"
)

var (
	process_ = "412314ljkaFSFaf"
	monkey = "AES256Key-32fad#$!@"
	conf_url = "https://share.cdn.wenqi.us/ex/sl.apo"
)

var op = options{}

type options struct {
	server_user     string
	server_password string
	server_host string
	server_port int64
}

func (op *options) insert(val string) {

	pl := *op
	if pl.server_host == "" {
		op.server_host = val
		return
	}
	if pl.server_password == "" {
		op.server_password = val
		return
	}
	if pl.server_user == "" {
		op.server_user = val
		return
	}
	if pl.server_port == 0 {
		op.server_port, _ = strconv.ParseInt(val, 0, 32)
		return
	}
}


func get_client(user, password, host string, port int64) (*ssh.Client, error) {
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		client       *ssh.Client
		err          error
	)
	// get auth method
	auth = make([]ssh.AuthMethod, 0)
	auth = append(auth, ssh.Password(password))

	clientConfig = &ssh.ClientConfig{
		User:    user,
		Auth:    auth,
		Timeout: 30 * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	// connet to ssh
	addr = fmt.Sprintf("%s:%d", host, port)

	if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return nil, err
	}

	return client,err

}

func connect_ssh(user, password, host string, port int64) (*ssh.Session, error) {
	client, err := get_client(user, password, host, port)

	session, err := client.NewSession();

	return session, err

}

func connect_scp(user, password, host string, port int64) (*sftp.Client, error) {
	client, err := get_client(user, password, host, port)
	if err != nil {
		return nil, err
	}
	session, err := sftp.NewClient(client)
	return session, err

}

func copy_file_from_server(srcPath,dstPath,filename string)  {
	client, err := connect_scp(op.server_user, op.server_password, op.server_host, op.server_port)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	srcFile, err := client.Open(srcPath + filename)
	defer srcFile.Close()

	dstFile, err := os.Create(dstPath + filename)
	if err != nil {
		log.Fatal(err)
	}
	defer dstFile.Close()

	srcFile.WriteTo(dstFile)
	if err != nil {
		log.Fatal(err)
	}
}

func run_with_terminal(cmd string)  {
	session, err := connect_ssh(op.server_user, op.server_password, op.server_host, op.server_port)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	fd := int(os.Stdin.Fd())
	oldState, err := terminal.MakeRaw(fd)
	if err != nil {
		panic(err)
	}
	defer terminal.Restore(fd, oldState)

	// excute command
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	termWidth, termHeight, err := terminal.GetSize(fd)
	if err != nil {
		panic(err)
	}

	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // enable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	// Request pseudo terminal
	if err := session.RequestPty("xterm-256color", termHeight, termWidth, modes); err != nil {
		log.Fatal(err)
	}

	session.Run(cmd)
}

func normal_run(cmd string) string {
	session, err := connect_ssh(op.server_user, op.server_password, op.server_host, op.server_port)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	session.Stderr = os.Stderr
	session.Run(cmd)

	return b.String()
}

func clean_bytes(bs []byte) []byte {
	var buffer bytes.Buffer

	for _, v := range bs {
		if v == 0x0 || v == 254 || v == 255 {
			continue
		}
		buffer.WriteByte(v)
	}
	return buffer.Bytes()
}



func sendRespG(url string) (*simplejson.Json, error) {


	var respBody = []byte(``)

	req, err := http.NewRequest("GET", url, bytes.NewBuffer(respBody))
	//req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	data,_ := ioutil.ReadAll(resp.Body)
	bs := clean_bytes(data)

	js, err := simplejson.NewJson(bs)

	return js, err

}

func get_parameters() error {

	js, err := sendRespG(conf_url)
	if err != nil {
		return err
	}

	for k, _ := range [4]int{} {
		ints := js.Get("key" + strconv.Itoa(k+1)).MustString()
		op.insert(_decrypt(ints))

	}
	return nil
}

func _decrypt(val string) string{

	key := []byte(monkey)

	ciphertext, _ := hex.DecodeString(val)

	nonce, _ := hex.DecodeString(process_)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return string(plaintext)
}

func main()  {
	get_parameters()
	process()
}


func process() {

	if len(os.Args) < 2 {
		fmt.Println("Not Enough Arguments \nSee at http://vinkdong.com/Speed")
		return
	}

	download_url := os.Args[1]
	//
	url_split := strings.Split(download_url, "/")

	delete_download := false

	fmt.Println("-----Vink Speed Downloader ------")


	//
	if len(url_split) >= 2 {
		for _, os_v := range os.Args {
			if os_v == "-d" {
				delete_download = true
			}
		}
		file_name := url_split[len(url_split)-1]
		run_with_terminal("wget " + download_url)
		fmt.Sprintf("downloaded file %s from %s", file_name, download_url)
		srcPath := strings.Replace(normal_run("pwd"), "\n", "", -1) + "/"
		copy_file_from_server(srcPath, "./", file_name)
		fmt.Printf("copied file %s from %s to %s \n", file_name, srcPath, "./")

		if delete_download {
			normal_run(fmt.Sprintf("cd %s | rm -f %s", srcPath, file_name))
			fmt.Printf("deleted file %s in server %s", file_name, srcPath)
		}
	}
}