import {
  GetBucketCorsCommand,
  PutBucketCorsCommand,
  DeleteBucketCorsCommand,
} from "@aws-sdk/client-s3";
import type { CorsRule } from "./types";
import { getS3Client } from "./s3-client";
import { GarageS3Error } from "./errors";

export async function getBucketCors(bucket: string): Promise<CorsRule[]> {
  const client = getS3Client();
  try {
    const result = await client.send(
      new GetBucketCorsCommand({ Bucket: bucket }),
    );
    return (
      result.CORSRules?.map((rule) => ({
        allowedOrigins: rule.AllowedOrigins ?? [],
        allowedMethods: rule.AllowedMethods ?? [],
        allowedHeaders: rule.AllowedHeaders ?? [],
        exposeHeaders: rule.ExposeHeaders,
        maxAgeSeconds: rule.MaxAgeSeconds,
      })) ?? []
    );
  } catch (err: unknown) {
    const error = err as { name?: string; $metadata?: { httpStatusCode?: number } };
    if (
      error.name === "NoSuchCORSConfiguration" ||
      error.name === "NotFound" ||
      error.$metadata?.httpStatusCode === 404
    ) {
      return [];
    }
    throw toS3Error(err);
  }
}

export async function putBucketCors(
  bucket: string,
  rules: CorsRule[],
): Promise<void> {
  const client = getS3Client();
  try {
    await client.send(
      new PutBucketCorsCommand({
        Bucket: bucket,
        CORSConfiguration: {
          CORSRules: rules.map((rule) => ({
            AllowedOrigins: rule.allowedOrigins,
            AllowedMethods: rule.allowedMethods,
            AllowedHeaders: rule.allowedHeaders,
            ExposeHeaders: rule.exposeHeaders,
            MaxAgeSeconds: rule.maxAgeSeconds,
          })),
        },
      }),
    );
  } catch (err: unknown) {
    throw toS3Error(err);
  }
}

export async function deleteBucketCors(bucket: string): Promise<void> {
  const client = getS3Client();
  try {
    await client.send(new DeleteBucketCorsCommand({ Bucket: bucket }));
  } catch (err: unknown) {
    throw toS3Error(err);
  }
}

function toS3Error(err: unknown): unknown {
  const error = err as { name?: string; Code?: string; $metadata?: { httpStatusCode?: number } };
  const status = error.$metadata?.httpStatusCode;
  if (status) {
    return new GarageS3Error(
      `S3 CORS request failed: ${error.name ?? error.Code ?? "Unknown"}`,
      status,
      error.name === "AccessDenied"
        ? "The configured S3 key does not have permission to manage CORS on this bucket."
        : undefined,
    );
  }
  return err;
}
