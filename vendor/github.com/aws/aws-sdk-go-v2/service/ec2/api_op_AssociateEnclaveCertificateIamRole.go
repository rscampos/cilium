// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Associates an Identity and Access Management (IAM) role with an Certificate
// Manager (ACM) certificate. This enables the certificate to be used by the ACM
// for Nitro Enclaves application inside an enclave. For more information, see
// Certificate Manager for Nitro Enclaves
// (https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-refapp.html) in
// the Amazon Web Services Nitro Enclaves User Guide. When the IAM role is
// associated with the ACM certificate, the certificate, certificate chain, and
// encrypted private key are placed in an Amazon S3 location that only the
// associated IAM role can access. The private key of the certificate is encrypted
// with an Amazon Web Services managed key that has an attached attestation-based
// key policy. To enable the IAM role to access the Amazon S3 object, you must
// grant it permission to call s3:GetObject on the Amazon S3 bucket returned by the
// command. To enable the IAM role to access the KMS key, you must grant it
// permission to call kms:Decrypt on the KMS key returned by the command. For more
// information, see  Grant the role permission to access the certificate and
// encryption key
// (https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-refapp.html#add-policy)
// in the Amazon Web Services Nitro Enclaves User Guide.
func (c *Client) AssociateEnclaveCertificateIamRole(ctx context.Context, params *AssociateEnclaveCertificateIamRoleInput, optFns ...func(*Options)) (*AssociateEnclaveCertificateIamRoleOutput, error) {
	if params == nil {
		params = &AssociateEnclaveCertificateIamRoleInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "AssociateEnclaveCertificateIamRole", params, optFns, c.addOperationAssociateEnclaveCertificateIamRoleMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*AssociateEnclaveCertificateIamRoleOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type AssociateEnclaveCertificateIamRoleInput struct {

	// The ARN of the ACM certificate with which to associate the IAM role.
	CertificateArn *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	// The ARN of the IAM role to associate with the ACM certificate. You can associate
	// up to 16 IAM roles with an ACM certificate.
	RoleArn *string

	noSmithyDocumentSerde
}

type AssociateEnclaveCertificateIamRoleOutput struct {

	// The name of the Amazon S3 bucket to which the certificate was uploaded.
	CertificateS3BucketName *string

	// The Amazon S3 object key where the certificate, certificate chain, and encrypted
	// private key bundle are stored. The object key is formatted as follows:
	// role_arn/certificate_arn.
	CertificateS3ObjectKey *string

	// The ID of the KMS key used to encrypt the private key of the certificate.
	EncryptionKmsKeyId *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationAssociateEnclaveCertificateIamRoleMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpAssociateEnclaveCertificateIamRole{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpAssociateEnclaveCertificateIamRole{}, middleware.After)
	if err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddClientRequestIDMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddComputeContentLengthMiddleware(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = v4.AddComputePayloadSHA256Middleware(stack); err != nil {
		return err
	}
	if err = addRetryMiddlewares(stack, options); err != nil {
		return err
	}
	if err = addHTTPSignerV4Middleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opAssociateEnclaveCertificateIamRole(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opAssociateEnclaveCertificateIamRole(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "AssociateEnclaveCertificateIamRole",
	}
}
