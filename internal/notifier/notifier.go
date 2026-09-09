package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"time"
)

// Notifier sends messages and documents to Telegram.
type Notifier struct {
	token  string
	chatID string
	client *http.Client
}

// New creates a Notifier; returns nil when not configured.
func New(token, chatID string) *Notifier {
	if token == "" || chatID == "" {
		return nil
	}
	return &Notifier{token: token, chatID: chatID, client: &http.Client{Timeout: 30 * time.Second}}
}

// SendText sends an HTML-formatted message.
func (n *Notifier) SendText(text string) bool {
	if n == nil {
		return false
	}
	payload := map[string]string{
		"chat_id":    n.chatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.token)
	resp, err := n.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("Telegram error: %v", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		log.Println("✅ Mensaje enviado a Telegram")
		return true
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	log.Printf("Telegram sendMessage status %d: %s", resp.StatusCode, string(data))
	return false
}

// SendFile uploads a document to Telegram with an optional caption.
func (n *Notifier) SendFile(path, caption string) bool {
	if n == nil {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		log.Printf("Telegram: archivo no existe: %v", err)
		return false
	}
	defer f.Close()

	var buf bytes.Buffer
	mp := multipart.NewWriter(&buf)
	_ = mp.WriteField("chat_id", n.chatID)
	_ = mp.WriteField("caption", caption)
	fw, err := mp.CreateFormFile("document", fileBase(path))
	if err != nil {
		return false
	}
	if _, err := io.Copy(fw, f); err != nil {
		return false
	}
	mp.Close()

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", n.token)
	req, err := http.NewRequest(http.MethodPost, url, &buf)
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", mp.FormDataContentType())
	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("Telegram error: %v", err)
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func fileBase(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
