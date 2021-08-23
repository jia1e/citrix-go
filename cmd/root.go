/*
Copyright © 2021 NAME HERE zhangjialecn@gmail.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/spf13/viper"

	"github.com/go-resty/resty/v2"
	"github.com/skratchdot/open-golang/open"
)

type Resource struct {
	Clienttypes           []string `json:"clienttypes"`
	Iconurl               string   `json:"iconurl"`
	Id                    string   `json:"id"`
	Launchstatusurl       string   `json:"launchstatusurl"`
	Launchurl             string   `json:"launchurl"`
	Name                  string   `json:"name"`
	Path                  string   `json:"path"`
	Shortcutvalidationurl string   `json:"shortcutvalidationurl"`
	Subscriptionurl       string   `json:"subscriptionurl"`
}

type ListResponseBody struct {
	Unauthorized           bool       `json:"unauthorized"`
	IsSubscriptionEnabled  bool       `json:"isSubscriptionEnabled"`
	IsUnauthenticatedStore bool       `json:"isUnauthenticatedStore"`
	Resources              []Resource `json:"resources"`
}

type GetDetectionTicketResponseBody struct {
	ClientDetectionStaTicket string `json:"clientDetectionStaTicket"`
	ClientDetectionTicket    string `json:"clientDetectionTicket"`
	PostbackUrl              string `json:"postbackUrl"`
	ServerProtocolVersion    string `json:"serverProtocolVersion"`
	Status                   string `json:"status"`
}

type GetDetectionStatusResponseBody struct {
	Status                   string `json:"status"`
	HdxIsPassThrough         string `json:"hdxIsPassThrough"`
	HdxIsPassThroughVariable string `json:"hdxIsPassThroughVariable"`
	HdxVersion               string `json:"hdxVersion"`
}

type GetLaunchStatusResponseBody struct {
	FileFetchStaTicket    string `json:"fileFetchStaTicket"`
	FileFetchTicket       string `json:"fileFetchTicket"`
	FileFetchUrl          string `json:"fileFetchUrl"`
	ServerProtocolVersion string `json:"serverProtocolVersion"`
	Status                string `json:"status"`
}

var cfgFile string
var save bool

var client = resty.New().
	SetHeader("X-Citrix-IsUsingHTTPS", "Yes")

func Login(user string, password string) {
	fd := make(map[string]string)
	fd["login"] = user
	fd["dummy_username"] = ""
	fd["dummy_pass1"] = ""
	fd["passwd"] = password

	res, err := client.R().
		SetFormData(fd).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Post("/cgi/login")

	if err != nil {
		panic(err)
	}

	for _, cookie := range res.Cookies() {
		if cookie.Name == "NSC_AAAC" {
			client.SetCookie(&http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			})
			return
		}
	}
}

func Configuration() {
	res, err := client.R().
		Post("/Citrix/StoreWeb/Home/Configuration")

	if err != nil {
		panic(err)
	}

	for _, cookie := range res.Cookies() {

		if cookie.Name == "CsrfToken" || cookie.Name == "ASP.NET_SessionId" {
			client.SetCookie(&http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			})

			if cookie.Name == "CsrfToken" {
				client.SetHeader("Csrf-Token", cookie.Value)
			}
		}
	}
}

type CallReceiverOptions struct {
	Endpoint              string
	Action                string
	ServerProtocolVersion string
	Transport             string
	Ticket                string
	StaTicket             string
}

func CallReceiver(options *CallReceiverOptions) {
	qs := strings.Join([]string{
		"action=" + options.Action,
		"serverProtocolVersion=" + options.ServerProtocolVersion,
		"transport=" + options.Transport,
		"ticket=" + options.Ticket,
		"staTicket=" + options.StaTicket,
	}, "&")

	u := url.URL{
		Scheme: "receiver",
		Host:   viper.GetString("host"),
		Path: "Citrix/Store/clientAssistant/" + options.Endpoint +
			base64.StdEncoding.EncodeToString([]byte(qs)) +
			"--",
	}

	open.Run(u.String())
}

func GetDetectionTicket() {

	result := GetDetectionTicketResponseBody{}

	client.R().
		SetResult(&result).
		SetHeader("Accept", "application/json").
		Post("/Citrix/StoreWeb/ClientAssistant/GetDetectionTicket")

	ch := make(chan GetDetectionStatusResponseBody)

	go GetDetectionStatus(result.ClientDetectionTicket, ch)

	CallReceiver(&CallReceiverOptions{
		Endpoint:              "reportDetectionStatus/",
		Action:                "detect",
		Transport:             "https",
		ServerProtocolVersion: result.ServerProtocolVersion,
		Ticket:                result.ClientDetectionTicket,
		StaTicket:             url.PathEscape(result.ClientDetectionStaTicket),
	})

	status := <-ch

	if status.Status != "Success" {
		panic(errors.New("检测不到 Citrix Receiver"))
	}
}

func GetDetectionStatus(ticket string, ch chan GetDetectionStatusResponseBody) {

	fd := make(map[string]string)
	fd["ticket"] = ticket

	for i := 0; i < 10; i++ {
		result := GetDetectionStatusResponseBody{}

		_, err := client.R().
			SetResult(&result).
			SetHeader("Accept", "application/json").
			SetFormData(fd).
			Post("/Citrix/StoreWeb/ClientAssistant/GetDetectionStatus")

		if err != nil {
			break
		}

		if result.Status == "Waiting" {
			time.Sleep(1 * time.Second)
			continue
		}

		ch <- result
		return
	}

	ch <- GetDetectionStatusResponseBody{
		Status: "Failure",
	}
}

func GetAuthMethods() {
	client.R().
		SetHeader("Accept", "application/xml, text/xml, */*; q=0.01").
		Post("/Citrix/StoreWeb/Authentication/GetAuthMethods")
}

func GatewayAuthLogin() {

	res, _ := client.R().
		Post("/Citrix/StoreWeb/GatewayAuth/Login")

	for _, cookie := range res.Cookies() {
		if cookie.Name == "CtxsAuthId" {
			client.SetCookie(&http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			})
			return
		}
	}
}

func List() (*[]Resource, error) {
	fd := make(map[string]string)
	fd["format"] = "json"
	fd["resourceDetails"] = "Default"

	res, err := client.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Accept", "application/json").
		SetFormData(fd).
		Post("/Citrix/StoreWeb/Resources/List")

	if err != nil {
		return nil, err
	}

	result := ListResponseBody{}

	json.Unmarshal(res.Body(), &result)

	if result.Unauthorized {

		for _, cookie := range res.Cookies() {
			if cookie.Name == "CtxsDeviceId" {
				client.SetCookie(&http.Cookie{
					Name:  cookie.Name,
					Value: cookie.Value,
				})
				break
			}
		}

		GetAuthMethods()
		GatewayAuthLogin()
		return List()
	} else {
		return &result.Resources, nil
	}
}

func Launch(resource *Resource) {

	fd := make(map[string]string)

	fd["displayNameDesktopTitle"] = url.PathEscape(resource.Name)
	fd["createFileFetchTicket"] = "true"

	result := GetLaunchStatusResponseBody{}

	_, err := client.R().
		SetResult(&result).
		SetHeader("Accept", "application/json").
		SetFormData(fd).
		Post("/Citrix/StoreWeb/" + resource.Launchstatusurl)

	if err == nil {
		CallReceiver(&CallReceiverOptions{
			Endpoint:              "getIcaFile/",
			Action:                "launch",
			Transport:             "https",
			ServerProtocolVersion: result.ServerProtocolVersion,
			Ticket:                result.FileFetchTicket,
			StaTicket:             url.PathEscape(result.FileFetchStaTicket),
		})
	}
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "citrix-go resource",
	Short: "",
	Long:  ``,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		var (
			host     = viper.GetString("host")
			user     = viper.GetString("user")
			password = viper.GetString("password")
		)

		openResource := viper.GetString("default-resource")

		if len(args) == 1 {
			openResource = args[0]
		}

		if len(args) > 1 || openResource == "" {
			fmt.Println("citrix-go [<options>] <resource> ")
			os.Exit(1)
		}

		fmt.Printf("host: %s \n", host)
		fmt.Printf("user: %s \n", user)
		fmt.Printf("openResource: %s\n", openResource)

		if save {
			viper.Set("host", host)
			viper.Set("user", user)
			viper.Set("password", password)
			viper.Set("default-resource", openResource)
			viper.WriteConfig()
		}

		client.SetHostURL("https://" + host)

		Login(user, password)
		Configuration()
		GetDetectionTicket()
		resources, err := List()

		if err != nil {
			panic(err)
		}

		for _, resource := range *resources {
			if resource.Name == openResource {
				fmt.Printf("Launch %s\n", resource.Name)
				Launch(&resource)
				return
			}
		}

		fmt.Printf("Resource %s not found", openResource)
		os.Exit(1)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is $HOME/.citrix-go.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	rootCmd.Flags().StringP("host", "H", "", "Citrix server")

	rootCmd.Flags().StringP("user", "u", "", "Username")

	rootCmd.Flags().StringP("password", "p", "", "Password")

	rootCmd.Flags().BoolVarP(&save, "save", "s", false, "Write to config file")

	viper.BindPFlag("host", rootCmd.Flags().Lookup("host"))

	viper.BindPFlag("user", rootCmd.Flags().Lookup("user"))

	viper.BindPFlag("password", rootCmd.Flags().Lookup("password"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".citrix-go" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".citrix-go")
	}

	viper.SetEnvPrefix("CITRIX")
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
