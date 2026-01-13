package storage

import (
	"context"
	"fmt"
	"io"

	"cdn-service/internal/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type FileInfo struct {
	ContentType   string
	ContentLength int64
	ETag          string
	LastModified  string
}

type Storage interface {
	Get(ctx context.Context, key string) (io.ReadCloser, *FileInfo, error)
	GetRange(ctx context.Context, key string, start, end int64) (io.ReadCloser, *FileInfo, error)
	Head(ctx context.Context, key string) (*FileInfo, error)
	Exists(ctx context.Context, key string) bool
}

type S3Storage struct {
	client *s3.Client
	bucket string
}

func NewS3Storage(cfg *config.Config) (*S3Storage, error) {
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		if cfg.S3Endpoint != "" {
			return aws.Endpoint{
				URL:               cfg.S3Endpoint,
				HostnameImmutable: true,
			}, nil
		}
		return aws.Endpoint{}, &aws.EndpointNotFoundError{}
	})

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(cfg.S3Region),
		awsconfig.WithEndpointResolverWithOptions(customResolver),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.S3AccessKey,
			cfg.S3SecretKey,
			"",
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	return &S3Storage{
		client: client,
		bucket: cfg.S3Bucket,
	}, nil
}

func (s *S3Storage) Get(ctx context.Context, key string) (io.ReadCloser, *FileInfo, error) {
	output, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, nil, err
	}

	info := &FileInfo{
		ContentType:   *output.ContentType,
		ContentLength: *output.ContentLength,
	}
	if output.ETag != nil {
		info.ETag = *output.ETag
	}
	if output.LastModified != nil {
		info.LastModified = output.LastModified.Format("Mon, 02 Jan 2006 15:04:05 GMT")
	}

	return output.Body, info, nil
}

func (s *S3Storage) GetRange(ctx context.Context, key string, start, end int64) (io.ReadCloser, *FileInfo, error) {
	rangeHeader := fmt.Sprintf("bytes=%d-%d", start, end)

	output, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Range:  aws.String(rangeHeader),
	})
	if err != nil {
		return nil, nil, err
	}

	info := &FileInfo{
		ContentType:   *output.ContentType,
		ContentLength: *output.ContentLength,
	}
	if output.ETag != nil {
		info.ETag = *output.ETag
	}

	return output.Body, info, nil
}

func (s *S3Storage) Head(ctx context.Context, key string) (*FileInfo, error) {
	output, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}

	info := &FileInfo{
		ContentType:   *output.ContentType,
		ContentLength: *output.ContentLength,
	}
	if output.ETag != nil {
		info.ETag = *output.ETag
	}
	if output.LastModified != nil {
		info.LastModified = output.LastModified.Format("Mon, 02 Jan 2006 15:04:05 GMT")
	}

	return info, nil
}

func (s *S3Storage) Exists(ctx context.Context, key string) bool {
	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	return err == nil
}
