// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Gets information about the associations for the specified transit gateway route
// table.
func (c *Client) GetTransitGatewayRouteTableAssociations(ctx context.Context, params *GetTransitGatewayRouteTableAssociationsInput, optFns ...func(*Options)) (*GetTransitGatewayRouteTableAssociationsOutput, error) {
	if params == nil {
		params = &GetTransitGatewayRouteTableAssociationsInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "GetTransitGatewayRouteTableAssociations", params, optFns, c.addOperationGetTransitGatewayRouteTableAssociationsMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*GetTransitGatewayRouteTableAssociationsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type GetTransitGatewayRouteTableAssociationsInput struct {

	// The ID of the transit gateway route table.
	//
	// This member is required.
	TransitGatewayRouteTableId *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	// One or more filters. The possible values are:
	//
	// * resource-id - The ID of the
	// resource.
	//
	// * resource-type - The resource type. Valid values are vpc | vpn |
	// direct-connect-gateway | peering | connect.
	//
	// * transit-gateway-attachment-id -
	// The ID of the attachment.
	Filters []types.Filter

	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	MaxResults *int32

	// The token for the next page of results.
	NextToken *string

	noSmithyDocumentSerde
}

type GetTransitGatewayRouteTableAssociationsOutput struct {

	// Information about the associations.
	Associations []types.TransitGatewayRouteTableAssociation

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationGetTransitGatewayRouteTableAssociationsMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpGetTransitGatewayRouteTableAssociations{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpGetTransitGatewayRouteTableAssociations{}, middleware.After)
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
	if err = addOpGetTransitGatewayRouteTableAssociationsValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opGetTransitGatewayRouteTableAssociations(options.Region), middleware.Before); err != nil {
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

// GetTransitGatewayRouteTableAssociationsAPIClient is a client that implements the
// GetTransitGatewayRouteTableAssociations operation.
type GetTransitGatewayRouteTableAssociationsAPIClient interface {
	GetTransitGatewayRouteTableAssociations(context.Context, *GetTransitGatewayRouteTableAssociationsInput, ...func(*Options)) (*GetTransitGatewayRouteTableAssociationsOutput, error)
}

var _ GetTransitGatewayRouteTableAssociationsAPIClient = (*Client)(nil)

// GetTransitGatewayRouteTableAssociationsPaginatorOptions is the paginator options
// for GetTransitGatewayRouteTableAssociations
type GetTransitGatewayRouteTableAssociationsPaginatorOptions struct {
	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// GetTransitGatewayRouteTableAssociationsPaginator is a paginator for
// GetTransitGatewayRouteTableAssociations
type GetTransitGatewayRouteTableAssociationsPaginator struct {
	options   GetTransitGatewayRouteTableAssociationsPaginatorOptions
	client    GetTransitGatewayRouteTableAssociationsAPIClient
	params    *GetTransitGatewayRouteTableAssociationsInput
	nextToken *string
	firstPage bool
}

// NewGetTransitGatewayRouteTableAssociationsPaginator returns a new
// GetTransitGatewayRouteTableAssociationsPaginator
func NewGetTransitGatewayRouteTableAssociationsPaginator(client GetTransitGatewayRouteTableAssociationsAPIClient, params *GetTransitGatewayRouteTableAssociationsInput, optFns ...func(*GetTransitGatewayRouteTableAssociationsPaginatorOptions)) *GetTransitGatewayRouteTableAssociationsPaginator {
	if params == nil {
		params = &GetTransitGatewayRouteTableAssociationsInput{}
	}

	options := GetTransitGatewayRouteTableAssociationsPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &GetTransitGatewayRouteTableAssociationsPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.NextToken,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *GetTransitGatewayRouteTableAssociationsPaginator) HasMorePages() bool {
	return p.firstPage || (p.nextToken != nil && len(*p.nextToken) != 0)
}

// NextPage retrieves the next GetTransitGatewayRouteTableAssociations page.
func (p *GetTransitGatewayRouteTableAssociationsPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*GetTransitGatewayRouteTableAssociationsOutput, error) {
	if !p.HasMorePages() {
		return nil, fmt.Errorf("no more pages available")
	}

	params := *p.params
	params.NextToken = p.nextToken

	var limit *int32
	if p.options.Limit > 0 {
		limit = &p.options.Limit
	}
	params.MaxResults = limit

	result, err := p.client.GetTransitGatewayRouteTableAssociations(ctx, &params, optFns...)
	if err != nil {
		return nil, err
	}
	p.firstPage = false

	prevToken := p.nextToken
	p.nextToken = result.NextToken

	if p.options.StopOnDuplicateToken &&
		prevToken != nil &&
		p.nextToken != nil &&
		*prevToken == *p.nextToken {
		p.nextToken = nil
	}

	return result, nil
}

func newServiceMetadataMiddleware_opGetTransitGatewayRouteTableAssociations(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "GetTransitGatewayRouteTableAssociations",
	}
}
