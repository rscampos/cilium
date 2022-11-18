// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"time"
)

// Archives an Amazon EBS snapshot. When you archive a snapshot, it is converted to
// a full snapshot that includes all of the blocks of data that were written to the
// volume at the time the snapshot was created, and moved from the standard tier to
// the archive tier. For more information, see Archive Amazon EBS snapshots
// (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/snapshot-archive.html) in
// the Amazon Elastic Compute Cloud User Guide.
func (c *Client) ModifySnapshotTier(ctx context.Context, params *ModifySnapshotTierInput, optFns ...func(*Options)) (*ModifySnapshotTierOutput, error) {
	if params == nil {
		params = &ModifySnapshotTierInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "ModifySnapshotTier", params, optFns, c.addOperationModifySnapshotTierMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*ModifySnapshotTierOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type ModifySnapshotTierInput struct {

	// The ID of the snapshot.
	//
	// This member is required.
	SnapshotId *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	// The name of the storage tier. You must specify archive.
	StorageTier types.TargetStorageTier

	noSmithyDocumentSerde
}

type ModifySnapshotTierOutput struct {

	// The ID of the snapshot.
	SnapshotId *string

	// The date and time when the archive process was started.
	TieringStartTime *time.Time

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationModifySnapshotTierMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpModifySnapshotTier{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpModifySnapshotTier{}, middleware.After)
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
	if err = addOpModifySnapshotTierValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opModifySnapshotTier(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opModifySnapshotTier(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "ModifySnapshotTier",
	}
}
