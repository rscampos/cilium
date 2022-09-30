// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Associates a CIDR block with your subnet. You can only associate a single IPv6
// CIDR block with your subnet. An IPv6 CIDR block must have a prefix length of
// /64.
func (c *Client) AssociateSubnetCidrBlock(ctx context.Context, params *AssociateSubnetCidrBlockInput, optFns ...func(*Options)) (*AssociateSubnetCidrBlockOutput, error) {
	if params == nil {
		params = &AssociateSubnetCidrBlockInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "AssociateSubnetCidrBlock", params, optFns, c.addOperationAssociateSubnetCidrBlockMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*AssociateSubnetCidrBlockOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type AssociateSubnetCidrBlockInput struct {

	// The IPv6 CIDR block for your subnet. The subnet must have a /64 prefix length.
	//
	// This member is required.
	Ipv6CidrBlock *string

	// The ID of your subnet.
	//
	// This member is required.
	SubnetId *string

	noSmithyDocumentSerde
}

type AssociateSubnetCidrBlockOutput struct {

	// Information about the IPv6 association.
	Ipv6CidrBlockAssociation *types.SubnetIpv6CidrBlockAssociation

	// The ID of the subnet.
	SubnetId *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationAssociateSubnetCidrBlockMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpAssociateSubnetCidrBlock{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpAssociateSubnetCidrBlock{}, middleware.After)
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
	if err = addOpAssociateSubnetCidrBlockValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opAssociateSubnetCidrBlock(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opAssociateSubnetCidrBlock(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "AssociateSubnetCidrBlock",
	}
}
