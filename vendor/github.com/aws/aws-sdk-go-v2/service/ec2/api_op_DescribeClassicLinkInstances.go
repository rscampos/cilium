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

// Describes one or more of your linked EC2-Classic instances. This request only
// returns information about EC2-Classic instances linked to a VPC through
// ClassicLink. You cannot use this request to return information about other
// instances. We are retiring EC2-Classic. We recommend that you migrate from
// EC2-Classic to a VPC. For more information, see Migrate from EC2-Classic to a
// VPC (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/vpc-migrate.html) in
// the Amazon Elastic Compute Cloud User Guide.
func (c *Client) DescribeClassicLinkInstances(ctx context.Context, params *DescribeClassicLinkInstancesInput, optFns ...func(*Options)) (*DescribeClassicLinkInstancesOutput, error) {
	if params == nil {
		params = &DescribeClassicLinkInstancesInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeClassicLinkInstances", params, optFns, c.addOperationDescribeClassicLinkInstancesMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeClassicLinkInstancesOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeClassicLinkInstancesInput struct {

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	// One or more filters.
	//
	// * group-id - The ID of a VPC security group that's
	// associated with the instance.
	//
	// * instance-id - The ID of the instance.
	//
	// * tag: -
	// The key/value combination of a tag assigned to the resource. Use the tag key in
	// the filter name and the tag value as the filter value. For example, to find all
	// resources that have a tag with the key Owner and the value TeamA, specify
	// tag:Owner for the filter name and TeamA for the filter value.
	//
	// * tag-key - The
	// key of a tag assigned to the resource. Use this filter to find all resources
	// assigned a tag with a specific key, regardless of the tag value.
	//
	// * vpc-id - The
	// ID of the VPC to which the instance is linked. vpc-id - The ID of the VPC that
	// the instance is linked to.
	Filters []types.Filter

	// One or more instance IDs. Must be instances linked to a VPC through ClassicLink.
	InstanceIds []string

	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	// Constraint: If the value is greater than 1000, we return only 1000 items.
	MaxResults *int32

	// The token for the next page of results.
	NextToken *string

	noSmithyDocumentSerde
}

type DescribeClassicLinkInstancesOutput struct {

	// Information about one or more linked EC2-Classic instances.
	Instances []types.ClassicLinkInstance

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeClassicLinkInstancesMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeClassicLinkInstances{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeClassicLinkInstances{}, middleware.After)
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeClassicLinkInstances(options.Region), middleware.Before); err != nil {
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

// DescribeClassicLinkInstancesAPIClient is a client that implements the
// DescribeClassicLinkInstances operation.
type DescribeClassicLinkInstancesAPIClient interface {
	DescribeClassicLinkInstances(context.Context, *DescribeClassicLinkInstancesInput, ...func(*Options)) (*DescribeClassicLinkInstancesOutput, error)
}

var _ DescribeClassicLinkInstancesAPIClient = (*Client)(nil)

// DescribeClassicLinkInstancesPaginatorOptions is the paginator options for
// DescribeClassicLinkInstances
type DescribeClassicLinkInstancesPaginatorOptions struct {
	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	// Constraint: If the value is greater than 1000, we return only 1000 items.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeClassicLinkInstancesPaginator is a paginator for
// DescribeClassicLinkInstances
type DescribeClassicLinkInstancesPaginator struct {
	options   DescribeClassicLinkInstancesPaginatorOptions
	client    DescribeClassicLinkInstancesAPIClient
	params    *DescribeClassicLinkInstancesInput
	nextToken *string
	firstPage bool
}

// NewDescribeClassicLinkInstancesPaginator returns a new
// DescribeClassicLinkInstancesPaginator
func NewDescribeClassicLinkInstancesPaginator(client DescribeClassicLinkInstancesAPIClient, params *DescribeClassicLinkInstancesInput, optFns ...func(*DescribeClassicLinkInstancesPaginatorOptions)) *DescribeClassicLinkInstancesPaginator {
	if params == nil {
		params = &DescribeClassicLinkInstancesInput{}
	}

	options := DescribeClassicLinkInstancesPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &DescribeClassicLinkInstancesPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.NextToken,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeClassicLinkInstancesPaginator) HasMorePages() bool {
	return p.firstPage || (p.nextToken != nil && len(*p.nextToken) != 0)
}

// NextPage retrieves the next DescribeClassicLinkInstances page.
func (p *DescribeClassicLinkInstancesPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeClassicLinkInstancesOutput, error) {
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

	result, err := p.client.DescribeClassicLinkInstances(ctx, &params, optFns...)
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

func newServiceMetadataMiddleware_opDescribeClassicLinkInstances(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "DescribeClassicLinkInstances",
	}
}
