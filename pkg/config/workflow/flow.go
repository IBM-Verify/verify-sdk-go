package workflow

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"os"

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
	SourceFormat string    `json:"sourceFormat" yaml:"sourceFormat"`
	TargetFormat string    `json:"targetFormat" yaml:"targetFormat"`
}

func NewModelTransformClient() *ModelTransformClient {
	return &ModelTransformClient{}
}

func (c *ModelTransformClient) TransformModel(ctx context.Context, modelFile io.Reader, sourceFormat, targetFormat string) ([]byte, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	defaultErr := errorsx.G11NError("unable to transform model")

	// Create multipart form data
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add the model file
	part, err := writer.CreateFormFile("model", "model.file")
	if err != nil {
		vc.Logger.Errorf("Unable to create form file; err=%v", err)
		return nil, defaultErr
	}

	_, err = io.Copy(part, modelFile)
	if err != nil {
		vc.Logger.Errorf("Unable to copy model file; err=%v", err)
		return nil, defaultErr
	}

	// Add sourceformat parameter
	err = writer.WriteField("sourceformat", sourceFormat)
	if err != nil {
		vc.Logger.Errorf("Unable to write sourceformat field; err=%v", err)
		return nil, defaultErr
	}

	// Add targetformat parameter
	err = writer.WriteField("targetformat", targetFormat)
	if err != nil {
		vc.Logger.Errorf("Unable to write targetformat field; err=%v", err)
		return nil, defaultErr
	}

	// Close the writer to finalize the multipart form
	err = writer.Close()
	if err != nil {
		vc.Logger.Errorf("Unable to close multipart writer; err=%v", err)
		return nil, defaultErr
	}

	// Set up parameters
	params := &TransformModelParams{
		Authorization: "Bearer " + vc.Token,
	}

	// Create request editors for content type
	reqEditors := []openapi.RequestEditorFn{
		func(ctx context.Context, req *http.Request) error {
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
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to transform model"); err != nil {
			vc.Logger.Errorf("unable to transform the model; err=%s", err.Error())
			return nil, errorsx.G11NError("unable to transform the model; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to transform the model; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, errorsx.G11NError("unable to transform the model; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return resp.Body, nil
}

func (c *ModelTransformClient) TransformModelFromFile(ctx context.Context, filePath, sourceFormat, targetFormat string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, errorsx.G11NError("unable to open model file; err=%v", err)
	}
	defer file.Close()

	return c.TransformModel(ctx, file, sourceFormat, targetFormat)
}

func (c *ModelTransformClient) TransformModelFromRequest(ctx context.Context, req *ModelTransformRequest) ([]byte, error) {
	return c.TransformModel(ctx, req.ModelFile, req.SourceFormat, req.TargetFormat)
}
