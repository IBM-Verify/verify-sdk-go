package workflow

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

type ModelTransformClient struct {
	Client *http.Client
}

type TransformModelParams = openapi.TransformSourceModelToTargetModelParams
type TransformModelResponse = openapi.TransformSourceModelToTargetModelObject

type ModelTransformRequest struct {
	ModelFile    io.Reader `json:"-"`
	TargetFormat string    `json:"targetFormat" yaml:"targetFormat"`
	ModelPath    string    `json:"modelfile" yaml:"modelfile"`
}

func NewModelTransformClient() *ModelTransformClient {
	return &ModelTransformClient{}
}

func (c *ModelTransformClient) TransformModel(ctx context.Context, modelFile io.Reader, targetFormat string, filename string) ([]byte, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	defaultErr := errorsx.G11NError("unable to transform model")

	// Create multipart form data
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add the model file
	part, err := writer.CreateFormFile("model", filename)
	if err != nil {
		vc.Logger.Errorf("Unable to create form file; err=%v", err)
		return nil, defaultErr
	}

	_, err = io.Copy(part, modelFile)
	if err != nil {
		vc.Logger.Errorf("Unable to copy model file; err=%v", err)
		return nil, defaultErr
	}

	// Add the targetformat field
	err = writer.WriteField("targetformat", targetFormat)
	if err != nil {
		vc.Logger.Errorf("Unable to write targetformat field; err=%v", err)
		return nil, defaultErr
	}

	err = writer.Close()
	if err != nil {
		vc.Logger.Errorf("Unable to close multipart writer; err=%v", err)
		return nil, defaultErr
	}

	// Set up parameters
	params := &TransformModelParams{
		Authorization: "Bearer " + vc.Token,
	}

	reqEditors := []openapi.RequestEditorFn{
		func(ctx context.Context, req *http.Request) error {
			// Set the multipart form data as the request body
			req.Body = io.NopCloser(&buf)
			req.ContentLength = int64(buf.Len())
			req.Header.Set("Content-Type", writer.FormDataContentType())

			return nil
		},
	}

	// Make the API call
	resp, err := client.TransformSourceModelToTargetModelWithResponse(ctx, params, reqEditors...)
	if err != nil {
		vc.Logger.Errorf("Unable to transform model; err=%v", err)
		return nil, defaultErr
	}

	// Check response status
	if resp.StatusCode() != http.StatusOK {
		rawBody := string(resp.Body)

		// Log the raw body before calling HandleCommonErrors
		vc.Logger.Errorf("transform failed: code=%d, body=%s", resp.StatusCode(), rawBody)

		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to transform model"); err != nil {
			return nil, errorsx.G11NError("unable to transform the model; err=%s; rawBody=%s", err.Error(), rawBody)
		}

		return nil, errorsx.G11NError("unable to transform the model; code=%d, body=%s", resp.StatusCode(), rawBody)
	}

	return resp.Body, nil
}

func (c *ModelTransformClient) TransformModelFromFile(ctx context.Context, filePath, targetFormat string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, errorsx.G11NError("unable to open model file; err=%v", err)
	}
	defer file.Close()

	filename := filepath.Base(filePath)

	return c.TransformModel(ctx, file, targetFormat, filename)
}
