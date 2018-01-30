/**
 * This package provides structs which can read and write
 * AES encrypted data.
 */
package aesrw

import (
	"crypto/aes"
	"bufio"
	"bytes"
	"crypto/cipher"
	"errors"
	"crypto/rand"
	"io"
)

/**
 * Satisfies the Reader interfaces. Able to read data from an io.Reader
 * that was written with AESWriter.
 */
type AESReader struct {
	//Data stream to read from
	ds *bufio.Reader
	//Handles data which doesn't fit to chunk size
	nRem int
	rem []byte
	//For performing decryption of the data
	block cipher.Block
	mode cipher.BlockMode
}

/**
 * Satisfies the Writer interfaces. Able to write data to an io.Writer.
 * Note: Close() must be called in order to finalize the data stream.
 */
type AESWriter struct {
	//Data stream to write to
	ds io.Writer
	//Handles data which doesn't fit to chunk size
	nRem int
	rem []byte
	//For performing encryption of the data
	block cipher.Block
	mode cipher.BlockMode
}

/**
 * Perform encryption of a specified byte slice.
 * Note: Encryption is not performed in-place.
 * @param b	The data to encrypt
 * @param key	The key to use for encryption
 * @return	The encrypted data and and any error
 */
func Encrypt(b, key []byte) ([]byte, error) {
	//Data to be read
	buf := bytes.NewBuffer(b)
	//Buffer to write to
	outBuf := new(bytes.Buffer)
	aw, err := NewWriter(outBuf, key)
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(aw, buf)
	if err != nil {
		return nil, err
	}
	aw.Close()
	return outBuf.Bytes(), nil
}

/**
 * Perform encryption of a specified string.
 * Note: Encryption is not performed in-place.
 * @param b	The data to encrypt
 * @param key	The key to use for encryption
 * @return	The encrypted data and and any error
 */
func EncryptString(s string, key []byte) (string, error) {
	//Data to be read
	buf := bytes.NewBufferString(s)
	//Buffer to write to
	outBuf := new(bytes.Buffer)
	aw, err := NewWriter(outBuf, key)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(aw, buf)
	if err != nil {
		return "", err
	}
	aw.Close()
	return outBuf.String(), nil
}

/**
 * Perform decryption of a specified byte slice.
 * Note: Decryption is not performed in-place.
 * @param b	The data to decryption
 * @param key	The key to use for decryption
 * @return	The decrypted data and and any error
 */
func Decrypt(b, key []byte) ([]byte, error) {
	//Data to be read
	buf := bytes.NewBuffer(b)
	ar, err := NewReader(buf, key)
	if err != nil {
		return nil, err
	}
	//Buffer to write to
	outBuf := new(bytes.Buffer)
	bw := bufio.NewWriter(outBuf)
	_, err = io.Copy(bw, ar)
	if err != nil {
		return nil, err
	}
	return outBuf.Bytes(), nil
}

/**
 * Perform decryption of a specified string.
 * Note: Decryption is not performed in-place.
 * @param b	The data to decryption
 * @param key	The key to use for decryption
 * @return	The decrypted data and and any error
 */
func DecryptString(s string, key []byte) (string, error) {
	//Data to be read
	buf := bytes.NewBufferString(s)
	ar, err := NewReader(buf, key)
	if err != nil {
		return "", err
	}
	//Buffer to write to
	outBuf := new(bytes.Buffer)
	_, err = io.Copy(outBuf, ar)
	if err != nil {
		return "", err
	}
	return outBuf.String(), nil
}

/**
 * Initialize a new AESWriter, generate an IV and write it to
 * the stream.
 */
func NewWriter(w io.Writer, k []byte) (*AESWriter, error) {
	//Key must be of length 16, 24 or 32 bytes
	if len(k) != 16 && len(k) != 24 && len(k) != 32 {
		return nil, errors.New("Key must be of length 16, 24, or 32.")
	}
	//First block is IV; generate random IV and write to stream
	tmpBlock := make([]byte, aes.BlockSize)
	_, err := rand.Reader.Read(tmpBlock)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(tmpBlock)
	if err != nil {
		return nil, err
	}
	//Create a new block cipher from the key and IV
	blk, err := aes.NewCipher(k)
	mde := cipher.NewCBCEncrypter(blk, tmpBlock)
	return &AESWriter{ds: w, rem: make([]byte, aes.BlockSize), block: blk, mode: mde}, nil
}

/**
 * Finalizes the data stream. This must be called before the
 * data stream is complete.
 */
func (w *AESWriter) Close() error {
	//w.nRem should be less than one block in length
	nPad := aes.BlockSize - w.nRem
	for i := w.nRem; i < cap(w.rem); i++ {
		w.rem[i] = byte(nPad)
	}
	//Encrypt and write final block
	w.mode.CryptBlocks(w.rem, w.rem)
	w.ds.Write(w.rem)
	w.nRem = 0
	return nil
}

/**
 * Write data to the underlying io.Writer. Data is written in chunks
 * and any extra is buffered between calls.
 */
func (w *AESWriter) Write(b []byte) (nw int, err error) {
	if len(b) <= 0 {
		return 0, nil
	}
	//The amount that will actually be written including any existing remainder
	roundSize := ((len(b) + w.nRem) / aes.BlockSize) * aes.BlockSize
	//Actual amount of b to actually write on this call
	nbw := Max(roundSize - w.nRem, 0)
	if roundSize > 0 {	//Prevent any index out of bounds errors
		//Temporary buffer capable of holding remainder plus data from b
		buf := make([]byte, roundSize)
		//Copy any remaining data to temp buffer
		copy(buf, w.rem[0:w.nRem])
		//roundSize is always large enough to accomodate rem
		//Copy the data passed on this call
		copy(buf[w.nRem:], b[0:nbw])
		//There is no remainder at this point
		w.nRem = 0
		//Encrypt and write the buffer
		w.mode.CryptBlocks(buf, buf)
		w.ds.Write(buf)
	}
	//Keep track of remainder from this call
	copy(w.rem[w.nRem:], b[nbw:])
	w.nRem += (len(b) - nbw)
	return len(b), nil
}

/**
 * Create a new AESReader and read the IV from the stream.
 */
func NewReader(r io.Reader, k []byte) (*AESReader, error) {
	//Key must be of length 16, 24 or 32 bytes
	if len(k) != 16 && len(k) != 24 && len(k) != 32 {
		return nil, errors.New("Key must be of length 16, 24, or 32.")
	}
	tmpBlock := make([]byte, aes.BlockSize)
	//Needed to peek on the input stream in Read
	br := bufio.NewReader(r)
	//Read the IV from the stream
	nr, err := io.ReadFull(br, tmpBlock)
	if nr != aes.BlockSize || err != nil {
		return nil, err
	}
	//Create a new block cipher from the key and IV
	blk, err := aes.NewCipher(k)
	mde := cipher.NewCBCDecrypter(blk, tmpBlock)
	return &AESReader{ds: br, rem: make([]byte, aes.BlockSize), block: blk, mode: mde}, nil
}

/**
 * Read and decrypt data from the underlying io.Reader that was
 * encrypted using an AESWriter.
 */
func (r *AESReader) Read(b []byte) (n int, err error) {
	//Buffer has no capacity
	if cap(b) <= 0 {
		return 0, nil
	}
	//Still have r.nRem bytes; determine total number of bytes to read to fill buffer
	roundSize := ((len(b) - r.nRem) / aes.BlockSize) * aes.BlockSize
	if ((len(b) - r.nRem) % aes.BlockSize) > 0 {
		roundSize += aes.BlockSize
	}
	//Copy any data that was decrypted previously
	nr := copy(b, r.rem[0:r.nRem])
	//Update the remainder variabales
	copy(r.rem, r.rem[nr:])
	r.nRem -= nr
	if roundSize > 0 {	//Only necessary if buffer wasn't filled yet
		//Need to read and decode another chunk to fill b
		buf := make([]byte, roundSize)
		n, err = io.ReadFull(r.ds, buf)
		//Data was read but didn't fill roundSize; this might be okay
		if err == io.ErrUnexpectedEOF && n > 0 {
			err = nil	//Supress the error
		} else if (err == io.EOF && n == 0) {
			return nr, err //Valid EOF detected; notify caller end was reached
		} else if err != nil {
			return nr, err //Some other error occured
		}
		//Perform the decryption; valid stream will be a multiple of block length
		if n % aes.BlockSize != 0 {
			return nr, errors.New("Stream is not a valid AESRW stream.")
		}
		r.mode.CryptBlocks(buf[0:n], buf[0:n])
		//If stream is valid it will be a multiple of block size so this
		//effectively tests if another block is present
		_, err = r.ds.Peek(1)
		if err != nil {
			//Last block read contains padding that must be removed
			//Last byte indicates the amount of padding added by AESWriter
			nPad := int(buf[n - 1])
			n -= nPad
		}
		//Test if invalid padding value was supplied
		if n > len(buf) || n < 0 {
			return nr, errors.New("Stream is not a valid AESRW stream.")
		}
		buf = buf[0:n]
		//Copy enough data to fill b after any remainder from above
		ar := copy(b[nr:], buf)
		nr += ar
		//Buffer any remainder to next call
		r.nRem = copy(r.rem, buf[ar:])
		//If there is still a remainder left; suppress EOF error
		if r.nRem > 0 {
			err = nil
		}
	}
	return nr, err
}

//Returns max of 2 ints
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

//Returns the min of 2 ints
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}