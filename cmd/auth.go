package cmd

import (
	"fmt"

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
		token, err := lib.AWSLogin()

		if err != nil {
			fmt.Println("Error getting iam login data", err)
		}

		jwt, _ := lib.GetJWT(token, viper.GetString("role-name"), viper.GetString("claim-name"))

		if err != nil {
			fmt.Println("Error getting Token", err)
		}

		fmt.Println(jwt)
	},
}

func init() {
	RootCmd.AddCommand(authCmd)

	authCmd.Flags().StringP("vault-header", "v", "", "Additional header with which to sign the IAM request")
	authCmd.Flags().StringP("role-name", "r", "", "The role name to use ")
	viper.BindPFlags(authCmd.Flags())
}
