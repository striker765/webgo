package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// VTResponse armazena a resposta da API do VirusTotal
type VTResponse struct {
	ResponseCode int                    `json:"response_code"`
	VerboseMsg   string                 `json:"verbose_msg"`
	ScanID       string                 `json:"scan_id"`
	Permalink    string                 `json:"permalink"`
	Resource     string                 `json:"resource"`
	Scans        map[string]ScanDetails `json:"scans"`
}

// ScanDetails armazena os detalhes da verificação
type ScanDetails struct {
	Detected bool   `json:"detected"`
	Result   string `json:"result"`
	Update   string `json:"update"`
	Version  string `json:"version"`
}

func main() {
	r := gin.Default()

	// Rota principal
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	// Rota para lidar com a verificação de IP
	r.GET("/check-ip", func(c *gin.Context) {
		ip := c.Query("ip")

		// Chave da API do VirusTotal
		apiKey := "9858e80a2593bde69ce0906a6fd1e79a2b0df6c31004fab9f7dbce4d32df12c1"

		// URL da API do VirusTotal para verificar IPs
		url := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=%s&ip=%s", apiKey, ip)

		// Realiza a requisição GET para a API do VirusTotal
		resp, err := http.Get(url)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao chamar a API do VirusTotal"})
			return
		}
		defer resp.Body.Close()

		// Decodifica a resposta JSON
		var vtResponse VTResponse
		err = json.NewDecoder(resp.Body).Decode(&vtResponse)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao decodificar a resposta JSON"})
			return
		}

		// Verifica se o request foi bem sucedido
		if vtResponse.ResponseCode != 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": vtResponse.VerboseMsg})
			return
		}

		// Exibe os resultados da verificação em formato JSON
		c.JSON(http.StatusOK, vtResponse)
	})

	// Rota para lidar com a verificação de URL
	r.GET("/check-url", func(c *gin.Context) {
		url := c.Query("url")

		// Chave da API do VirusTotal
		apiKey := "sua-chave-de-api-aqui"

		// URL da API do VirusTotal para verificar URLs
		urlVT := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/url/report?apikey=%s&resource=%s", apiKey, url)

		// Realiza a requisição GET para a API do VirusTotal
		resp, err := http.Get(urlVT)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao chamar a API do VirusTotal"})
			return
		}
		defer resp.Body.Close()

		// Decodifica a resposta JSON
		var vtResponse VTResponse
		err = json.NewDecoder(resp.Body).Decode(&vtResponse)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao decodificar a resposta JSON"})
			return
		}

		// Verifica se o request foi bem sucedido
		if vtResponse.ResponseCode != 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": vtResponse.VerboseMsg})
			return
		}

		// Exibe os resultados da verificação em formato JSON
		c.JSON(http.StatusOK, vtResponse)
	})

	// Servir arquivos estáticos (por exemplo, HTML, CSS, JS)
	r.Static("/static", "./static")

	// Carregar templates HTML
	r.LoadHTMLGlob("/*")

	// Executar o servidor
	r.Run(":8080")
}
