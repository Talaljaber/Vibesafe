"use server";

import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";

const s3 = new S3Client({});

export async function uploadReport(formData: FormData) {
  const file = formData.get("report") as File;
  await s3.send(
    new PutObjectCommand({
      Bucket: process.env.REPORT_BUCKET,
      Key: file.name,
      Body: Buffer.from(await file.arrayBuffer()),
    }),
  );
}
