package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
)

const (
	magic = "TPMSEALv1"
)

// --- TPM helper functions ---
func openTPM() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM()
}

func writeBlobFile(path string, pub, priv []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write([]byte(magic)); err != nil {
		return err
	}
	if err := binary.Write(f, binary.LittleEndian, uint32(len(pub))); err != nil {
		return err
	}
	if err := binary.Write(f, binary.LittleEndian, uint32(len(priv))); err != nil {
		return err
	}
	if _, err := f.Write(pub); err != nil {
		return err
	}
	if _, err := f.Write(priv); err != nil {
		return err
	}
	return nil
}

func readBlobFile(path string) (pub, priv []byte, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	r := bytes.NewReader(b)
	h := make([]byte, len(magic))
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, nil, err
	}
	if string(h) != magic {
		return nil, nil, fmt.Errorf("bad blob format")
	}
	var plen, slen uint32
	if err := binary.Read(r, binary.LittleEndian, &plen); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &slen); err != nil {
		return nil, nil, err
	}
	pub = make([]byte, plen)
	priv = make([]byte, slen)
	if _, err := io.ReadFull(r, pub); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, priv); err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// --- TPM key template ---
func getDefaultKeyTemplate() tpm2.Public {
	return tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}
}

// --- Seal ---
func cmdSeal(secret, pin, out string) error {
	rwc, err := openTPM()
	if err != nil {
		return fmt.Errorf("openTPM: %w", err)
	}
	defer rwc.Close()

	// Create primary storage key
	primaryHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", getDefaultKeyTemplate())
	if err != nil {
		return fmt.Errorf("CreatePrimary: %w", err)
	}
	defer tpm2.FlushContext(rwc, primaryHandle)

	// Create sealed object with user PIN
	keyTemplate := tpm2.Public{
		Type:       tpm2.AlgKeyedHash,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagUserWithAuth | tpm2.FlagNoDA,
	}
	priv, pub, _, _, _, err := tpm2.CreateKeyWithSensitive(rwc, primaryHandle, tpm2.PCRSelection{}, "", pin, keyTemplate, []byte(secret))
	if err != nil {
		return fmt.Errorf("CreateKeyWithSensitive: %w", err)
	}

	// Write blob
	if err := writeBlobFile(out, pub, priv); err != nil {
		return fmt.Errorf("write blob: %w", err)
	}

	fmt.Printf("Sealed secret to %s. Use the PIN to unseal.\n", out)
	return nil
}

// --- Unseal ---
func cmdUnseal(pin, in string) error {
	rwc, err := openTPM()
	if err != nil {
		return fmt.Errorf("openTPM: %w", err)
	}
	defer rwc.Close()

	pub, priv, err := readBlobFile(in)
	if err != nil {
		return fmt.Errorf("read blob: %w", err)
	}

	// Create primary storage key
	primaryHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", getDefaultKeyTemplate())
	if err != nil {
		return fmt.Errorf("CreatePrimary: %w", err)
	}
	defer tpm2.FlushContext(rwc, primaryHandle)

	// Load sealed object with user PIN
	objHandle, _, err := tpm2.Load(rwc, primaryHandle, "", pub, priv)
	if err != nil {
		return fmt.Errorf("Load: %w", err)
	}
	defer tpm2.FlushContext(rwc, objHandle)

	// Unseal secret
	secret, err := tpm2.Unseal(rwc, objHandle, pin)
	if err != nil {
		return fmt.Errorf("Unseal: %w", err)
	}

	fmt.Printf("Unsealed secret: %s\n", string(secret))
	return nil
}

// --- Cobra CLI ---
func main() {
	var rootCmd = &cobra.Command{
		Use:   "tpmcli",
		Short: "TPM CLI to seal/unseal secrets with user PIN",
	}

	var sealCmd = &cobra.Command{
		Use:   "seal",
		Short: "Seal a secret with TPM and PIN",
		Run: func(cmd *cobra.Command, args []string) {
			secret, _ := cmd.Flags().GetString("secret")
			pin, _ := cmd.Flags().GetString("pin")
			out, _ := cmd.Flags().GetString("out")
			if secret == "" || pin == "" {
				log.Fatal("secret (-s) and pin (-p) required")
			}
			if err := cmdSeal(secret, pin, out); err != nil {
				log.Fatalf("seal failed: %v", err)
			}
		},
	}
	sealCmd.Flags().StringP("secret", "s", "", "Secret to seal (required)")
	sealCmd.Flags().StringP("pin", "p", "", "User PIN to protect the secret (required)")
	sealCmd.Flags().StringP("out", "o", "secret.blob", "Output blob file")

	var unsealCmd = &cobra.Command{
		Use:   "unseal",
		Short: "Unseal a secret from TPM using PIN",
		Run: func(cmd *cobra.Command, args []string) {
			pin, _ := cmd.Flags().GetString("pin")
			in, _ := cmd.Flags().GetString("in")
			if pin == "" {
				log.Fatal("PIN (-p) required")
			}
			if err := cmdUnseal(pin, in); err != nil {
				log.Fatalf("unseal failed: %v", err)
			}
		},
	}
	unsealCmd.Flags().StringP("pin", "p", "", "User PIN to unseal (required)")
	unsealCmd.Flags().StringP("in", "i", "secret.blob", "Input blob file")

	rootCmd.AddCommand(sealCmd)
	rootCmd.AddCommand(unsealCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
