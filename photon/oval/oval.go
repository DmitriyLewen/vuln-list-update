package oval

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	pb "github.com/cheggaaa/pb/v3"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	ovalURLFormat = "https://packages.broadcom.com/photon/photon_oval_definitions/com.vmware.phsa-photon%s.xml.gz"
	photonOvalDir = "photon-oval"
	retry         = 5
)

var photonVersions = []string{"1", "2", "3", "4", "5"}

type Config struct {
	VulnListDir string
	URLFormat   string
	AppFs       afero.Fs
	Retry       int
}

func NewConfig() Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		URLFormat:   ovalURLFormat,
		AppFs:       afero.NewOsFs(),
		Retry:       retry,
	}
}

func (c Config) Update() error {
	log.Printf("Fetching Photon OVAL")

	for _, ver := range photonVersions {
		if err := c.UpdateVersion(ver); err != nil {
			return xerrors.Errorf("failed to update Photon OVAL for version %s: %w", ver, err)
		}
	}

	return nil
}

func (c Config) UpdateVersion(photonVer string) error {
	url := fmt.Sprintf(c.URLFormat, photonVer)
	res, err := utils.FetchURL(url, "", c.Retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch Photon OVAL: %w", err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(res))
	if err != nil {
		return xerrors.Errorf("failed to decompress Photon OVAL: %w", err)
	}
	defer gr.Close()

	var ov OvalDefinitions
	if err = xml.NewDecoder(gr).Decode(&ov); err != nil {
		return xerrors.Errorf("failed to decode Photon OVAL XML: %w", err)
	}

	bar := pb.StartNew(len(ov.Definitions))
	for _, def := range ov.Definitions {
		def.Title = strings.TrimSpace(def.Title)
		def.Description = strings.TrimSpace(def.Description)

		phsaID, err := PhsaIDFromTitle(def.Title)
		if err != nil {
			log.Printf("invalid PHSA title: %s\n", def.Title)
			bar.Increment()
			continue
		}

		osVer := OsVersionFromCriteria(def.Criteria)
		if osVer == "" {
			log.Printf("failed to detect OS version for %s\n", phsaID)
			bar.Increment()
			continue
		}

		if err = c.savePHSA(osVer, phsaID, def); err != nil {
			return xerrors.Errorf("failed to save PHSA: %w", err)
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}

func (c Config) savePHSA(osVer, phsaID string, def Definition) error {
	dir := filepath.Join(c.VulnListDir, photonOvalDir, osVer)
	fileName := fmt.Sprintf("%s.json", phsaID)
	if err := utils.WriteJSON(c.AppFs, dir, fileName, def); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}

// PhsaIDFromTitle extracts a filesystem-safe PHSA advisory ID from a definition title.
// E.g. "PHSA-2026:00001 telegraf Security Update. (Moderate)" → "PHSA-2026-00001"
func PhsaIDFromTitle(title string) (string, error) {
	parts := strings.Fields(title)
	if len(parts) == 0 {
		return "", xerrors.New("empty title")
	}
	// Replace ":" with "-" to make it filesystem-safe
	id := strings.ReplaceAll(parts[0], ":", "-")
	s := strings.Split(id, "-")
	if len(s) < 3 || s[0] != "PHSA" {
		return "", xerrors.Errorf("unexpected PHSA ID format: %s", parts[0])
	}
	return id, nil
}

// OsVersionFromCriteria extracts the Photon OS version string from criteria.
// It looks for a criterion comment like "Photon OS 3 is installed" and returns "3.0".
func OsVersionFromCriteria(cri Criteria) string {
	for _, c := range cri.Criterions {
		if strings.HasPrefix(c.Comment, "Photon OS ") && strings.HasSuffix(c.Comment, " is installed") {
			ver := strings.TrimSuffix(strings.TrimPrefix(c.Comment, "Photon OS "), " is installed")
			return ver + ".0"
		}
	}
	for _, c := range cri.Criterias {
		if ver := OsVersionFromCriteria(*c); ver != "" {
			return ver
		}
	}
	return ""
}
