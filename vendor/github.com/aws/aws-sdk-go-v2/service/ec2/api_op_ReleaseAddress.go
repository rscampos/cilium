// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Releases the specified Elastic IP address. [EC2-Classic, default VPC] Releasing
// an Elastic IP address automatically disassociates it from any instance that it's
// associated with. To disassociate an Elastic IP address without releasing it, use
// DisassociateAddress. [Nondefault VPC] You must use DisassociateAddress to
// disassociate the Elastic IP address before you can release it. Otherwise, Amazon
// EC2 returns an error (InvalidIPAddress.InUse). After releasing an Elastic IP
// address, it is released to the IP address pool. Be sure to update your DNS
// records and any servers or devices that communicate with the address. If you
// attempt to release an Elastic IP address that you already released, you'll get
// an AuthFailure error if the address is already allocated to another Amazon Web
// Services account. [EC2-VPC] After you release an Elastic IP address for use in a
// VPC, you might be able to recover it. For more information, see AllocateAddress.
// For more information, see Elastic IP Addresses
// (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html)
// in the Amazon Elastic Compute Cloud User Guide.
func (c *Client) ReleaseAddress(ctx context.Context, params *ReleaseAddressInput, optFns ...func(*Options)) (*ReleaseAddressOutput, error) {
	if params == nil {
		params = &ReleaseAddressInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "ReleaseAddress", params, optFns, c.addOperationReleaseAddressMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*ReleaseAddressOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type ReleaseAddressInput struct {

	// [EC2-VPC] The allocation ID. Required for EC2-VPC.
	AllocationId *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	// The set of Availability Zones, Local Zones, or Wavelength Zones from which
	// Amazon Web Services advertises IP addresses. If you provide an incorrect network
	// border group, you receive an InvalidAddress.NotFound error. You cannot use a
	// network border group with EC2 Classic. If you attempt this operation on EC2
	// classic, you receive an InvalidParameterCombination error.
	NetworkBorderGroup *string

	// [EC2-Classic] The Elastic IP address. Required for EC2-Classic.
	PublicIp *string

	noSmithyDocumentSerde
}

type ReleaseAddressOutput struct {
	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationReleaseAddressMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpReleaseAddress{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpReleaseAddress{}, middleware.After)
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opReleaseAddress(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opReleaseAddress(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "ReleaseAddress",
	}
}
