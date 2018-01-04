package cmd

import (
	"fmt"
	"net/http"

	"github.com/siteminder-au/vault-iam-auth/lib"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// authCmd represents the auth command
var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate with Vault",
	Long: `Authenticate with the specified vault server, this will include 
getting the signed IAM request from AWS and then requesting the auth token
from the vault server`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("auth called")
		client := &http.Client{}

		iamData, err := lib.GenerateLoginData()
		if err != nil {
			fmt.Println("Error getting iam login data", err)
			return
		}

		token, err := lib.AWSLogin(client, *iamData)

		if err != nil {
			fmt.Println("Error signing into Vault", err)
			return
		}

		jwt, err := lib.GetJWT(client, token, viper.GetString("role-name"), viper.GetString("claim-name"))

		if err != nil {
			fmt.Println("Error getting Token", err)
			return
		}

		fmt.Println(jwt)
	},
}

func init() {
	RootCmd.AddCommand(authCmd)

	authCmd.Flags().StringP("vault-header", "v", "", "Additional header with which to sign the IAM request")
	authCmd.Flags().StringP("vault-url", "u", "http://127.0.0.1:8200", "The url of the vault server")
	authCmd.Flags().StringP("role-name", "r", "", "The role name to use")
	authCmd.Flags().StringP("claim-name", "c", "", "The name of the predefined claim set to append to the token")
	viper.BindPFlags(authCmd.Flags())
}
