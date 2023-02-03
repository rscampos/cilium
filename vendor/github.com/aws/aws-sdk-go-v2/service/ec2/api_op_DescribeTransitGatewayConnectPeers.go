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

// Describes one or more Connect peers.
func (c *Client) DescribeTransitGatewayConnectPeers(ctx context.Context, params *DescribeTransitGatewayConnectPeersInput, optFns ...func(*Options)) (*DescribeTransitGatewayConnectPeersOutput, error) {
	if params == nil {
		params = &DescribeTransitGatewayConnectPeersInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeTransitGatewayConnectPeers", params, optFns, c.addOperationDescribeTransitGatewayConnectPeersMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeTransitGatewayConnectPeersOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeTransitGatewayConnectPeersInput struct {

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	// One or more filters. The possible values are:
	//
	// * state - The state of the
	// Connect peer (pending | available | deleting | deleted).
	//
	// *
	// transit-gateway-attachment-id - The ID of the attachment.
	//
	// *
	// transit-gateway-connect-peer-id - The ID of the Connect peer.
	Filters []types.Filter

	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	MaxResults *int32

	// The token for the next page of results.
	NextToken *string

	// The IDs of the Connect peers.
	TransitGatewayConnectPeerIds []string

	noSmithyDocumentSerde
}

type DescribeTransitGatewayConnectPeersOutput struct {

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Information about the Connect peers.
	TransitGatewayConnectPeers []types.TransitGatewayConnectPeer

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeTransitGatewayConnectPeersMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeTransitGatewayConnectPeers{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeTransitGatewayConnectPeers{}, middleware.After)
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeTransitGatewayConnectPeers(options.Region), middleware.Before); err != nil {
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

// DescribeTransitGatewayConnectPeersAPIClient is a client that implements the
// DescribeTransitGatewayConnectPeers operation.
type DescribeTransitGatewayConnectPeersAPIClient interface {
	DescribeTransitGatewayConnectPeers(context.Context, *DescribeTransitGatewayConnectPeersInput, ...func(*Options)) (*DescribeTransitGatewayConnectPeersOutput, error)
}

var _ DescribeTransitGatewayConnectPeersAPIClient = (*Client)(nil)

// DescribeTransitGatewayConnectPeersPaginatorOptions is the paginator options for
// DescribeTransitGatewayConnectPeers
type DescribeTransitGatewayConnectPeersPaginatorOptions struct {
	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeTransitGatewayConnectPeersPaginator is a paginator for
// DescribeTransitGatewayConnectPeers
type DescribeTransitGatewayConnectPeersPaginator struct {
	options   DescribeTransitGatewayConnectPeersPaginatorOptions
	client    DescribeTransitGatewayConnectPeersAPIClient
	params    *DescribeTransitGatewayConnectPeersInput
	nextToken *string
	firstPage bool
}

// NewDescribeTransitGatewayConnectPeersPaginator returns a new
// DescribeTransitGatewayConnectPeersPaginator
func NewDescribeTransitGatewayConnectPeersPaginator(client DescribeTransitGatewayConnectPeersAPIClient, params *DescribeTransitGatewayConnectPeersInput, optFns ...func(*DescribeTransitGatewayConnectPeersPaginatorOptions)) *DescribeTransitGatewayConnectPeersPaginator {
	if params == nil {
		params = &DescribeTransitGatewayConnectPeersInput{}
	}

	options := DescribeTransitGatewayConnectPeersPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &DescribeTransitGatewayConnectPeersPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.NextToken,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeTransitGatewayConnectPeersPaginator) HasMorePages() bool {
	return p.firstPage || (p.nextToken != nil && len(*p.nextToken) != 0)
}

// NextPage retrieves the next DescribeTransitGatewayConnectPeers page.
func (p *DescribeTransitGatewayConnectPeersPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeTransitGatewayConnectPeersOutput, error) {
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

	result, err := p.client.DescribeTransitGatewayConnectPeers(ctx, &params, optFns...)
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

func newServiceMetadataMiddleware_opDescribeTransitGatewayConnectPeers(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "DescribeTransitGatewayConnectPeers",
	}
}
