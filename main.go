package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/DILEEPSAJJA/File_Encrypt/filecrypt"
)

func main() {
	router := gin.Default()

	router.StaticFile("/", "./static/index.html")

	router.POST("/encrypt", handleEncrypt)
	router.POST("/decrypt", handleDecrypt)

	fmt.Println("Server running on http://localhost:8081")
	router.Static("/static", "./static")
	router.Run(":8081")
}

func handleEncrypt(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, "File is required")
		return
	}

	password := c.PostForm("password")
	if len(password) < 4 {
		c.String(http.StatusBadRequest, "Password must be at least 4 characters")
		return
	}

	// Save uploaded file
	tempPath := filepath.Join(os.TempDir(), file.Filename)
	if err := c.SaveUploadedFile(file, tempPath); err != nil {
		c.String(http.StatusInternalServerError, "Failed to save uploaded file")
		return
	}
	defer os.Remove(tempPath) // clean up temp file

	encPath, err := filecrypt.EncryptFile(tempPath, []byte(password))
	if err != nil {
		c.String(http.StatusInternalServerError, "Encryption failed: %v", err)
		return
	}
	defer os.Remove(encPath) // clean up encrypted file

	c.FileAttachment(encPath, file.Filename+".enc")
}

func handleDecrypt(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, "File is required")
		return
	}

	password := c.PostForm("password")
	if len(password) < 4 {
		c.String(http.StatusBadRequest, "Password must be at least 4 characters")
		return
	}

	tempPath := filepath.Join(os.TempDir(), file.Filename)
	if err := c.SaveUploadedFile(file, tempPath); err != nil {
		c.String(http.StatusInternalServerError, "Failed to save uploaded file")
		return
	}
	defer os.Remove(tempPath)

	decPath, err := filecrypt.DecryptFile(tempPath, []byte(password))
	if err != nil {
		c.String(http.StatusBadRequest, "Decryption failed: %v", err)
		return
	}
	defer os.Remove(decPath)

	originalName := file.Filename[:len(file.Filename)-4] // remove .enc
	c.FileAttachment(decPath, originalName)
}