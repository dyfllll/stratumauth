using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Globalization;
using System.Text.RegularExpressions;
using System.Net.Http;


namespace Stratum.Droid
{
    //public class AWSConfig
    //{
    //    public static string SecretId = "";
    //    public static string SecretKey = "";
    //    public static string Endpoint = "";
    //    public static string Bucket = "";
    //    public static string Region = "us-east-1";
    //    public static bool ForcePathStyle = true;
    //    public static string UploadFolder = "";
    //}
    public class AWSUtility
    {
        public static string awsAccessKeyId => AWSConfig.SecretId;
        public static string awsSecretAccessKey => AWSConfig.SecretKey;
        public static string Endpoint => AWSConfig.Endpoint;

        #region const
        public const string Scheme = "AWS4";
        public const string Algorithm = "HMAC-SHA256";
        public const string Sigv4aAlgorithm = "ECDSA-P256-SHA256";

        public const string AWS4AlgorithmTag = Scheme + "-" + Algorithm;
        public const string AWS4aAlgorithmTag = Scheme + "-" + Sigv4aAlgorithm;

        public const string Terminator = "aws4_request";
        public static readonly byte[] TerminatorBytes = Encoding.UTF8.GetBytes(Terminator);

        public const string Credential = "Credential";
        public const string SignedHeaders = "SignedHeaders";
        public const string Signature = "Signature";

        public const string EmptyBodySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        public const string StreamingBodySha256 = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
        public const string StreamingBodySha256WithTrailer = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
        public const string V4aStreamingBodySha256 = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD";
        public const string V4aStreamingBodySha256WithTrailer = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER";
        public const string AWSChunkedEncoding = "aws-chunked";

        public const string UnsignedPayload = "UNSIGNED-PAYLOAD";
        public const string UnsignedPayloadWithTrailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

        const SigningAlgorithm SignerAlgorithm = SigningAlgorithm.HmacSHA256;
        public const string ISO8601BasicDateFormat = "yyyyMMdd";
        public const string ISO8601BasicDateTimeFormat = "yyyyMMddTHHmmssZ";

        private static IEnumerable<string> _headersToIgnoreWhenSigning = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            HeaderKeys.XAmznTraceIdHeader,
            HeaderKeys.TransferEncodingHeader,
            HeaderKeys.AmzSdkInvocationId,
            HeaderKeys.AmzSdkRequest
        };
        #endregion







        public static string PutUrl(string bucketName, string filename)
        {
            int expires = 86400;//24小时
            string resPath = string.Format("/{0}/{1}", bucketName, filename);
            Dictionary<string, string> Headers = new Dictionary<string, string>();
            Dictionary<string, string> Query = new Dictionary<string, string>();
            Query.Add(HeaderKeys.XAmzExpires, expires.ToString());
            string authorization = SignQuery(resPath, "PUT", Headers, null, Query);
            string url = string.Format("{0}{1}/{2}?{3}&{4}", Endpoint, bucketName, filename, string.Format("{0}={1}", HeaderKeys.XAmzExpires, expires), authorization);
            return url;
        }

        public static string GetUrl(string bucketName, string filename)
        {
            int expires = 86400;//24小时
            string resPath = string.Format("/{0}/{1}", bucketName, filename);
            Dictionary<string, string> Headers = new Dictionary<string, string>();
            Dictionary<string, string> Query = new Dictionary<string, string>();
            Query.Add(HeaderKeys.XAmzExpires, expires.ToString());
            string authorization = SignQuery(resPath, "GET", Headers, null, Query);
            string url = string.Format("{0}{1}/{2}?{3}&{4}", Endpoint, bucketName, filename, string.Format("{0}={1}", HeaderKeys.XAmzExpires, expires), authorization);
            return url;
        }

        public static string DeleteUrl(string bucketName, string filename)
        {
            int expires = 86400;//24小时
            string resPath = string.Format("/{0}/{1}", bucketName, filename);
            Dictionary<string, string> Headers = new Dictionary<string, string>();
            Dictionary<string, string> Query = new Dictionary<string, string>();
            Query.Add(HeaderKeys.XAmzExpires, expires.ToString());
            string authorization = SignQuery(resPath, "DELETE", Headers, null, Query);
            string url = string.Format("{0}{1}/{2}?{3}&{4}", Endpoint, bucketName, filename, string.Format("{0}={1}", HeaderKeys.XAmzExpires, expires), authorization);
            return url;
        }

        public static string HeadUrl(string bucketName, string filename)
        {
            int expires = 86400;//24小时
            string resPath = string.Format("/{0}/{1}", bucketName, filename);
            Dictionary<string, string> Headers = new Dictionary<string, string>();
            Dictionary<string, string> Query = new Dictionary<string, string>();
            Query.Add(HeaderKeys.XAmzExpires, expires.ToString());
            string authorization = SignQuery(resPath, "HEAD", Headers, null, Query);
            string url = string.Format("{0}{1}/{2}?{3}&{4}", Endpoint, bucketName, filename, string.Format("{0}={1}", HeaderKeys.XAmzExpires, expires), authorization);
            return url;
        }


        public static async Task<HttpResponseMessage> HttpListObjectAsync(string bucketName, string prefix, string delimiter = "", string startAfter = "",
                   int maxKeys = 1000, string continuationToken = "")
        {
            string encodeToken = string.IsNullOrEmpty(continuationToken) ? continuationToken : UrlEncode(continuationToken, false);
            string filename = "";
            string resPath = string.Format("/{0}/{1}", bucketName, filename);
            string url = $"{Endpoint}{bucketName}/{filename}?list-type=2&continuation-token={encodeToken}&delimiter={delimiter}&max-keys={maxKeys}&prefix={prefix}&start-after={startAfter}";

            using (var client = new HttpClient())
            {
                Dictionary<string, string> Querys = new Dictionary<string, string>();
                Querys.Add("list-type", "2");
                Querys.Add("continuation-token", continuationToken);
                Querys.Add("delimiter", delimiter);
                Querys.Add("max-keys", maxKeys.ToString());
                Querys.Add("prefix", prefix);
                Querys.Add("start-after", startAfter);


                Dictionary<string, string> Headers = new Dictionary<string, string>();
                string authorization = SignHeader(resPath, "GET", Headers, null, Querys);
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(AWS4AlgorithmTag, authorization);
                foreach (var pair in Headers)
                {
                    client.DefaultRequestHeaders.Add(pair.Key, pair.Value);
                }
                HttpResponseMessage res = await client.GetAsync(url);
                return res;
            }

        }


        /// <summary>
        /// 最大删除1000
        /// </summary>
        /// <param name="bucketName"></param>
        /// <param name="keys"></param>
        /// <param name="quiet"></param>
        /// <returns></returns>
        public static async Task<HttpResponseMessage> HttpDeletesAsync(string bucketName, List<string> keys, bool quiet)
        {
            StringBuilder sb = new StringBuilder();
            foreach (var item in keys)
            {
                sb.Append($"<Object><Key>{item}</Key></Object>");
            }
            string data = $"<Delete><Quiet>{quiet}</Quiet>{sb}</Delete>";

            byte[] bytes = Encoding.UTF8.GetBytes(data);


            string filename = "";
            string resPath = string.Format("/{0}/{1}", bucketName, filename);
            string url = string.Format("{0}{1}/{2}?delete", Endpoint, bucketName, filename);
            string contentType = "application/octet-stream";
            using (var client = new HttpClient())
            {
                byte[] contentMD5 = ComputeMd5Hash(bytes);

                Dictionary<string, string> Querys = new Dictionary<string, string>();
                Querys.Add("delete", null);

                Dictionary<string, string> Headers = new Dictionary<string, string>();
                Headers[HeaderKeys.ContentTypeHeader] = contentType;
                Headers[HeaderKeys.ContentMD5Header] = Convert.ToBase64String(contentMD5);
                string authorization = SignHeader(resPath, "POST", Headers, null, Querys);
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(AWS4AlgorithmTag, authorization);
                Headers.Remove(HeaderKeys.ContentTypeHeader);
                Headers.Remove(HeaderKeys.ContentMD5Header);
                foreach (var pair in Headers)
                {
                    client.DefaultRequestHeaders.Add(pair.Key, pair.Value);
                }
                HttpContent content = new ByteArrayContent(bytes);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
                content.Headers.ContentMD5 = contentMD5;

                HttpResponseMessage res = await client.PostAsync(url, content);
                return res;
            }
        }

        static byte[] ComputeMd5Hash(byte[] data)
        {
            using (MD5 md5 = MD5.Create())
            {
                return md5.ComputeHash(data);
            }
        }




        public static async Task<HttpResponseMessage> HttpPutAsync(string bucketName, string filename, byte[] bytes)
        {
            string resPath = string.Format("/{0}/{1}", bucketName, filename);
            string url = string.Format("{0}{1}/{2}", Endpoint, bucketName, filename);
            string contentType = "application/octet-stream";
            using (var client = new HttpClient())
            {
                Dictionary<string, string> Headers = new Dictionary<string, string>();
                Headers[HeaderKeys.ContentTypeHeader] = contentType;
                string authorization = SignHeader(resPath, "PUT", Headers, null, null);
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(AWS4AlgorithmTag, authorization);
                Headers.Remove(HeaderKeys.ContentTypeHeader);
                foreach (var pair in Headers)
                {
                    client.DefaultRequestHeaders.Add(pair.Key, pair.Value);
                }
                HttpContent content = new ByteArrayContent(bytes);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
                HttpResponseMessage res = await client.PutAsync(url, content);
                return res;
            }
        }


        public static async Task<HttpResponseMessage> HttpGetAsync(string bucketName, string filename)
        {
            string resPath = string.Format("/{0}/{1}", bucketName, filename);
            string url = string.Format("{0}{1}/{2}", Endpoint, bucketName, filename);

            using (var client = new HttpClient())
            {
                Dictionary<string, string> Headers = new Dictionary<string, string>();
                string authorization = SignHeader(resPath, "GET", Headers, null, null);
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(AWS4AlgorithmTag, authorization);

                foreach (var pair in Headers)
                {
                    client.DefaultRequestHeaders.Add(pair.Key, pair.Value);
                }
                HttpResponseMessage res = await client.GetAsync(url);
                return res;
            }
        }


        public static async Task<HttpResponseMessage> HttpDeleteAsync(string bucketName, string filename)
        {
            string resPath = string.Format("/{0}/{1}", bucketName, filename);
            string url = string.Format("{0}{1}/{2}", Endpoint, bucketName, filename);

            using (var client = new HttpClient())
            {
                Dictionary<string, string> Headers = new Dictionary<string, string>();
                string authorization = SignHeader(resPath, "DELETE", Headers, null, null);
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(AWS4AlgorithmTag, authorization);
                foreach (var pair in Headers)
                {
                    client.DefaultRequestHeaders.Add(pair.Key, pair.Value);
                }
                HttpResponseMessage res = await client.DeleteAsync(url);
                return res;
            }
        }


        public static async Task<HttpResponseMessage> HttpHeadAsync(string bucketName, string filename)
        {
            string resPath = string.Format("/{0}/{1}", bucketName, filename);
            string url = string.Format("{0}{1}/{2}", Endpoint, bucketName, filename);
            using (var client = new HttpClient())
            {
                Dictionary<string, string> Headers = new Dictionary<string, string>();
                string authorization = SignHeader(resPath, "HEAD", Headers, null, null);
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(AWS4AlgorithmTag, authorization);
                foreach (var pair in Headers)
                {
                    client.DefaultRequestHeaders.Add(pair.Key, pair.Value);
                }
                HttpResponseMessage res = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                return res;
            }
        }



        public static string SignQuery(string ResourcePath, string HttpMethod,
            IDictionary<string, string> Headers, IDictionary<string, string> PathResources, IDictionary<string, string> QueryParam)
        {
            SigningResult result = SignQueryRequest(ResourcePath, HttpMethod, Headers, PathResources, QueryParam);
            return result.ForQueryParameters;
        }


        public static string SignHeader(string ResourcePath, string HttpMethod,
            IDictionary<string, string> Headers, IDictionary<string, string> PathResources, IDictionary<string, string> QueryParam)
        {
            SigningResult result = SignHeaderRequest(ResourcePath, HttpMethod, Headers, PathResources, QueryParam);
            return result.ForAuthorizationHeader;
        }


        /// <summary>
        /// 链接方式签名
        /// </summary>
        public static SigningResult SignQueryRequest(string ResourcePath, string HttpMethod,
            IDictionary<string, string> Headers, IDictionary<string, string> PathResources, IDictionary<string, string> QueryParam)
        {
            Uri endpoint = new Uri(Endpoint);

            Headers.Remove(HeaderKeys.AuthorizationHeader);
            if (!Headers.ContainsKey(HeaderKeys.HostHeader))
            {
                var hostHeader = endpoint.Host;
                if (!endpoint.IsDefaultPort)
                    hostHeader += ":" + endpoint.Port;
                Headers.Add(HeaderKeys.HostHeader, hostHeader);
            }
            var signedAt = DateTime.UtcNow;
            var determinedSigningRegion = "us-east-1";
            var bodyHash = "UNSIGNED-PAYLOAD";
            var serviceSigningName = "s3";

            if (Headers.ContainsKey(HeaderKeys.XAmzContentSha256Header))
                Headers.Remove(HeaderKeys.XAmzContentSha256Header);
            var sortedHeaders = SortAndPruneHeaders(Headers);

            var canonicalizedHeaderNames = CanonicalizeHeaderNames(sortedHeaders);
            var parametersToCanonicalize = QueryParam != null ? QueryParam.ToList() : new List<KeyValuePair<string, string>>();
            parametersToCanonicalize.Add(new KeyValuePair<string, string>(HeaderKeys.XAmzAlgorithm, AWS4AlgorithmTag));
            var xAmzCredentialValue = string.Format(CultureInfo.InvariantCulture, "{0}/{1}/{2}/{3}/{4}",
                                                       awsAccessKeyId,
                                                       FormatDateTime(signedAt, ISO8601BasicDateFormat),
                                                       determinedSigningRegion,
                                                       serviceSigningName,
                                                       Terminator);
            parametersToCanonicalize.Add(new KeyValuePair<string, string>(HeaderKeys.XAmzCredential, xAmzCredentialValue));

            parametersToCanonicalize.Add(new KeyValuePair<string, string>(HeaderKeys.XAmzDateHeader, FormatDateTime(signedAt, ISO8601BasicDateTimeFormat)));
            parametersToCanonicalize.Add(new KeyValuePair<string, string>(HeaderKeys.XAmzSignedHeadersHeader, canonicalizedHeaderNames));

            var canonicalQueryParams = CanonicalizeQueryParameters(parametersToCanonicalize);

            var canonicalRequest = CanonicalizeRequest(endpoint,
                                                       ResourcePath,
                                                       HttpMethod,
                                                       sortedHeaders,
                                                       canonicalQueryParams,
                                                        bodyHash,
                                                       PathResources,
                                                       2,
                                                       serviceSigningName);

            return ComputeSignature(awsAccessKeyId,
                                    awsSecretAccessKey,
                                    determinedSigningRegion,
                                    signedAt,
                                    serviceSigningName,
                                    CanonicalizeHeaderNames(sortedHeaders),
                                    canonicalRequest
                                    );
        }


        /// <summary>
        /// header方式签名
        /// </summary>
        public static SigningResult SignHeaderRequest(string ResourcePath, string HttpMethod,
            IDictionary<string, string> Headers, IDictionary<string, string> PathResources, IDictionary<string, string> QueryParam)
        {
            Uri endpoint = new Uri(Endpoint);
            var signedAt = InitializeHeaders(Headers, endpoint, DateTime.UtcNow);
            var serviceSigningName = "s3";
            var determinedSigningRegion = "us-east-1";

            var parametersToCanonicalize = QueryParam != null ? QueryParam.ToList() : null;
            var canonicalParameters = CanonicalizeQueryParameters(parametersToCanonicalize);


            var bodyHash = "UNSIGNED-PAYLOAD";
            SetPayloadSignatureHeader(Headers, bodyHash);
            var sortedHeaders = SortAndPruneHeaders(Headers);

            var canonicalRequest = CanonicalizeRequest(endpoint,
                                                       ResourcePath,
                                                       HttpMethod,
                                                       sortedHeaders,
                                                       canonicalParameters,
                                                       bodyHash,
                                                       PathResources,
                                                       2,
                                                       serviceSigningName);


            return ComputeSignature(awsAccessKeyId,
                                    awsSecretAccessKey,
                                    determinedSigningRegion,
                                    signedAt,
                                    serviceSigningName,
                                    CanonicalizeHeaderNames(sortedHeaders),
                                    canonicalRequest
                                    );
        }





        static string SetPayloadSignatureHeader(IDictionary<string, string> Headers, string payloadHash)
        {
            if (Headers.ContainsKey(HeaderKeys.XAmzContentSha256Header))
                Headers[HeaderKeys.XAmzContentSha256Header] = payloadHash;
            else
                Headers.Add(HeaderKeys.XAmzContentSha256Header, payloadHash);

            return payloadHash;
        }


        public static string FormatDateTime(DateTime dt, string formatString)
        {
            return dt.ToUniversalTime().ToString(formatString, CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Computes the non-keyed hash of the supplied data
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] ComputeHash(string data)
        {
            return ComputeHash(Encoding.UTF8.GetBytes(data));
        }


        public static SigningResult ComputeSignature(string awsAccessKey,
                                                 string awsSecretAccessKey,
                                                 string region,
                                                 DateTime signedAt,
                                                 string service,
                                                 string signedHeaders,
                                                 string canonicalRequest
                                               )
        {
            var dateStamp = FormatDateTime(signedAt, ISO8601BasicDateFormat);
            var scope = string.Format(CultureInfo.InvariantCulture, "{0}/{1}/{2}/{3}", dateStamp, region, service, Terminator);

            var stringToSignBuilder = new StringBuilder();
            stringToSignBuilder.AppendFormat(CultureInfo.InvariantCulture, "{0}-{1}\n{2}\n{3}\n",
                                      Scheme,
                                      Algorithm,
                                      FormatDateTime(signedAt, ISO8601BasicDateTimeFormat),
                                      scope);

            var canonicalRequestHashBytes = ComputeHash(canonicalRequest);
            stringToSignBuilder.Append(AWSSDKUtilsToHex(canonicalRequestHashBytes, true));


            var key = ComposeSigningKey(awsSecretAccessKey,
                                        region,
                                        dateStamp,
                                        service);

            var stringToSign = stringToSignBuilder.ToString();
            var signature = ComputeKeyedHash(SignerAlgorithm, key, stringToSign);

            //var authorizationHeader = new StringBuilder()
            //     .Append(AWS4AlgorithmTag)
            //     .AppendFormat(" {0}={1}/{2},", Credential, awsAccessKey, scope)
            //     .AppendFormat(" {0}={1},", SignedHeaders, signedHeaders)
            //     .AppendFormat(" {0}={1}", Signature, AWSSDKUtilsToHex(signature, true));

            //var authorizationHeader = new StringBuilder()
            // .AppendFormat("{0}={1}/{2},", Credential, awsAccessKey, scope)
            // .AppendFormat(" {0}={1},", SignedHeaders, signedHeaders)
            // .AppendFormat(" {0}={1}", Signature, AWSSDKUtilsToHex(signature, true));

            //return authorizationHeader.ToString();
            return new SigningResult(awsAccessKey, signedAt, signedHeaders, scope, key, signature);
        }


        public static byte[] ComposeSigningKey(string awsSecretAccessKey, string region, string date, string service)
        {
            char[] ksecret = null;

            try
            {
                ksecret = (Scheme + awsSecretAccessKey).ToCharArray();

                var hashDate = ComputeKeyedHash(SignerAlgorithm, Encoding.UTF8.GetBytes(ksecret), Encoding.UTF8.GetBytes(date));
                var hashRegion = ComputeKeyedHash(SignerAlgorithm, hashDate, Encoding.UTF8.GetBytes(region));
                var hashService = ComputeKeyedHash(SignerAlgorithm, hashRegion, Encoding.UTF8.GetBytes(service));
                return ComputeKeyedHash(SignerAlgorithm, hashService, TerminatorBytes);
            }
            finally
            {
                // clean up all secrets, regardless of how initially seeded (for simplicity)
                if (ksecret != null)
                    Array.Clear(ksecret, 0, ksecret.Length);
            }
        }

        protected static string CanonicalizeRequest(Uri endpoint,
                                            string resourcePath,
                                            string httpMethod,
                                            IDictionary<string, string> sortedHeaders,
                                            string canonicalQueryString,
                                            string precomputedBodyHash,
                                            IDictionary<string, string> pathResources,
                                            int marshallerVersion,
                                            string service)
        {
            return CanonicalizeRequestHelper(endpoint,
                resourcePath,
                httpMethod,
                sortedHeaders,
                canonicalQueryString,
                precomputedBodyHash,
                pathResources,
                marshallerVersion,
                !(service == "s3"));
        }

        private static string CanonicalizeRequestHelper(Uri endpoint,
                                                    string resourcePath,
                                                    string httpMethod,
                                                    IDictionary<string, string> sortedHeaders,
                                                    string canonicalQueryString,
                                                    string precomputedBodyHash,
                                                    IDictionary<string, string> pathResources,
                                                    int marshallerVersion,
                                                    bool detectPreEncode)
        {
            var canonicalRequest = new StringBuilder();
            canonicalRequest.AppendFormat("{0}\n", httpMethod);
            canonicalRequest.AppendFormat("{0}\n", CanonicalizeResourcePath(endpoint, resourcePath, detectPreEncode, pathResources, marshallerVersion));
            canonicalRequest.AppendFormat("{0}\n", canonicalQueryString);

            canonicalRequest.AppendFormat("{0}\n", CanonicalizeHeaders(sortedHeaders));
            canonicalRequest.AppendFormat("{0}\n", CanonicalizeHeaderNames(sortedHeaders));

            if (precomputedBodyHash != null)
            {
                canonicalRequest.Append(precomputedBodyHash);
            }
            else
            {
                string contentHash;
                if (sortedHeaders.TryGetValue(HeaderKeys.XAmzContentSha256Header, out contentHash))
                    canonicalRequest.Append(contentHash);
            }

            return canonicalRequest.ToString();
        }

        protected internal static string CanonicalizeHeaders(IEnumerable<KeyValuePair<string, string>> sortedHeaders)
        {
            if (sortedHeaders == null || sortedHeaders.Count() == 0)
                return string.Empty;

            var builder = new StringBuilder();

            foreach (var entry in sortedHeaders)
            {
                // Refer https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html. (Step #4: "To create the canonical headers list, convert all header names to lowercase and remove leading spaces and trailing spaces. Convert sequential spaces in the header value to a single space.").
                builder.Append(entry.Key.ToLowerInvariant());
                builder.Append(":");
                builder.Append(CompressSpaces(entry.Value)?.Trim());
                builder.Append("\n");
            }
            return builder.ToString();
        }

        protected static string CanonicalizeHeaderNames(IEnumerable<KeyValuePair<string, string>> sortedHeaders)
        {
            var builder = new StringBuilder();

            foreach (var header in sortedHeaders)
            {
                if (builder.Length > 0)
                    builder.Append(";");
                builder.Append(header.Key.ToLowerInvariant());
            }

            return builder.ToString();
        }


        protected internal static IDictionary<string, string> SortAndPruneHeaders(IEnumerable<KeyValuePair<string, string>> requestHeaders)
        {
            // Refer https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html. (Step #4: "Build the canonical headers list by sorting the (lowercase) headers by character code"). StringComparer.OrdinalIgnoreCase incorrectly places '_' after lowercase chracters.
            var sortedHeaders = new SortedDictionary<string, string>(StringComparer.Ordinal);
            foreach (var header in requestHeaders)
            {
                if (_headersToIgnoreWhenSigning.Contains(header.Key))
                {
                    continue;
                }
                sortedHeaders.Add(header.Key.ToLowerInvariant(), header.Value);
            }

            return sortedHeaders;
        }





        /// <summary>
        /// Sets the AWS4 mandated 'host' and 'x-amz-date' headers, accepting and returning the date/time that will
        /// be used throughout the signing process in various elements and formats.
        /// </summary>
        /// <param name = "headers" > The current set of headers</param>
        /// <param name = "requestEndpoint" ></ param >
        /// < param name= "requestDateTime" ></ param >
        /// < returns > Date and time used for x-amz-date, in UTC</returns>
        public static DateTime InitializeHeaders(IDictionary<string, string> headers, Uri requestEndpoint, DateTime requestDateTime)
        {
            //clean up any prior signature in the headers if resigning
            CleanHeaders(headers);

            if (!headers.ContainsKey(HeaderKeys.HostHeader))
            {
                var hostHeader = requestEndpoint.Host;
                if (!requestEndpoint.IsDefaultPort)
                    hostHeader += ":" + requestEndpoint.Port;
                headers.Add(HeaderKeys.HostHeader, hostHeader);
            }

            var dt = requestDateTime;
            headers[HeaderKeys.XAmzDateHeader] = dt.ToUniversalTime().ToString(ISO8601BasicDateTimeFormat, CultureInfo.InvariantCulture);

            return dt;
        }

        private static void CleanHeaders(IDictionary<string, string> headers)
        {
            headers.Remove(HeaderKeys.AuthorizationHeader);
            headers.Remove(HeaderKeys.XAmzContentSha256Header);

            if (headers.ContainsKey(HeaderKeys.XAmzDecodedContentLengthHeader))
            {
                headers[HeaderKeys.ContentLengthHeader] =
                    headers[HeaderKeys.XAmzDecodedContentLengthHeader];
                headers.Remove(HeaderKeys.XAmzDecodedContentLengthHeader);
            }
        }


        public class SigningResult
        {
            private readonly byte[] _signingKey;
            private readonly byte[] _signature;
            private readonly string _awsAccessKeyId;
            private readonly DateTime _originalDateTime;
            private readonly string _signedHeaders;
            private readonly string _scope;

            public SigningResult(string awsAccessKeyId,
                                 DateTime signedAt,
                                 string signedHeaders,
                                 string scope,
                                 byte[] signingKey,
                                 byte[] signature)
            {
                _signingKey = signingKey;
                _signature = signature;
                _awsAccessKeyId = awsAccessKeyId;
                _originalDateTime = signedAt;
                _signedHeaders = signedHeaders;
                _scope = scope;
            }


            public byte[] GetSigningKey()
            {
                var kSigningCopy = new byte[_signingKey.Length];
                _signingKey.CopyTo(kSigningCopy, 0);
                return kSigningCopy;
            }

            public string Signature
            {
                get { return AWSUtility.AWSSDKUtilsToHex(_signature, true); }
            }



            /// <summary>
            /// The access key that was used in signature computation.
            /// </summary>
            public string AccessKeyId
            {
                get { return _awsAccessKeyId; }
            }

            /// <summary>
            /// ISO8601 formatted date/time that the signature was computed
            /// </summary>
            public string ISO8601DateTime
            {
                get { return AWSUtility.FormatDateTime(_originalDateTime, AWSUtility.ISO8601BasicDateTimeFormat); }
            }

            /// <summary>
            /// ISO8601 formatted date that the signature was computed
            /// </summary>
            public string ISO8601Date
            {
                get { return AWSUtility.FormatDateTime(_originalDateTime, AWSUtility.ISO8601BasicDateFormat); }
            }

            /// <summary>
            /// Original date/time that the signature was computed
            /// </summary>
            public DateTime DateTime
            {
                get { return _originalDateTime; }
            }

            /// <summary>
            /// The ;-delimited collection of header names that were included in the signature computation
            /// </summary>
            public string SignedHeaders
            {
                get { return _signedHeaders; }
            }

            /// <summary>
            /// Formatted 'scope' value for signing (YYYYMMDD/region/service/aws4_request)
            /// </summary>
            public string Scope
            {
                get { return _scope; }
            }


            public string ForAuthorizationHeader
            {
                get
                {
                    var authorizationHeader = new StringBuilder()
                        //.Append(AWSUtility.AWS4AlgorithmTag)
                        .AppendFormat("{0}={1}/{2},", AWSUtility.Credential, AccessKeyId, Scope)
                        .AppendFormat(" {0}={1},", AWSUtility.SignedHeaders, SignedHeaders)
                        .AppendFormat(" {0}={1}", AWSUtility.Signature, Signature);

                    return authorizationHeader.ToString();
                }
            }


            public string ForQueryParameters
            {
                get
                {
                    var authParams = new StringBuilder()
                        .AppendFormat("{0}={1}", HeaderKeys.XAmzAlgorithm, AWSUtility.AWS4AlgorithmTag)
                        .AppendFormat("&{0}={1}", HeaderKeys.XAmzCredential, string.Format(CultureInfo.InvariantCulture, "{0}/{1}", AccessKeyId, Scope))
                        .AppendFormat("&{0}={1}", HeaderKeys.XAmzDateHeader, ISO8601DateTime)
                        .AppendFormat("&{0}={1}", HeaderKeys.XAmzSignedHeadersHeader, SignedHeaders)
                        .AppendFormat("&{0}={1}", HeaderKeys.XAmzSignature, Signature);
                    return authParams.ToString();
                }
            }
        }

        public enum SigningAlgorithm
        {
            HmacSHA1,
            HmacSHA256
        };

        public abstract class HeaderKeys
        {
            public const string IfModifiedSinceHeader = "If-Modified-Since";
            public const string IfMatchHeader = "If-Match";
            public const string IfNoneMatchHeader = "If-None-Match";
            public const string IfUnmodifiedSinceHeader = "If-Unmodified-Since";
            public const string ConfirmSelfBucketAccess = "x-amz-confirm-remove-self-bucket-access";
            public const string ContentRangeHeader = "Content-Range";
            public const string ContentTypeHeader = "Content-Type";
            public const string ContentLengthHeader = "Content-Length";
            public const string ContentMD5Header = "Content-MD5";
            public const string ContentEncodingHeader = "Content-Encoding";
            public const string ContentDispositionHeader = "Content-Disposition";
            public const string ETagHeader = "ETag";
            public const string Expires = "Expires";
            public const string AuthorizationHeader = "Authorization";
            public const string HostHeader = "host";
            public const string UserAgentHeader = "User-Agent";
            public const string LocationHeader = "location";
            public const string DateHeader = "Date";
            public const string RangeHeader = "Range";
            public const string ExpectHeader = "Expect";
            public const string AcceptHeader = "Accept";
            public const string ConnectionHeader = "Connection";
            public const string StatusHeader = "Status";
            public const string XHttpMethodOverrideHeader = "X-HTTP-Method-Override";
            public const string TransferEncodingHeader = "transfer-encoding";

            public const string RequestIdHeader = "x-amzn-RequestId";
            public const string XAmzId2Header = "x-amz-id-2";
            public const string XAmzCloudFrontIdHeader = "X-Amz-Cf-Id";
            public const string XAmzRequestIdHeader = "x-amz-request-id";
            public const string XAmzDateHeader = "X-Amz-Date";
            public const string XAmzErrorType = "x-amzn-ErrorType";
            public const string XAmznErrorMessage = "x-amzn-error-message";
            public const string XAmzSignedHeadersHeader = "X-Amz-SignedHeaders";
            public const string XAmzContentSha256Header = "X-Amz-Content-SHA256";
            public const string XAmzDecodedContentLengthHeader = "X-Amz-Decoded-Content-Length";
            public const string XAmzSecurityTokenHeader = "x-amz-security-token";
            public const string XAmzAuthorizationHeader = "X-Amzn-Authorization";
            public const string XAmzRegionSetHeader = "X-Amz-Region-Set";
            public const string XAmzNonceHeader = "x-amz-nonce";
            public const string XAmzServerSideEncryptionHeader = "x-amz-server-side-encryption";
            public const string XAmzServerSideEncryptionAwsKmsKeyIdHeader = "x-amz-server-side-encryption-aws-kms-key-id";
            public const string XAmzBucketRegion = "x-amz-bucket-region";
            public const string XAmzAccountId = "x-amz-account-id";
            public const string XAmzOutpostId = "x-amz-outpost-id";
            public const string XAmzApiVersion = "x-amz-api-version";
            public const string XAmzExpires = "X-Amz-Expires";
            public const string XAmzSignature = "X-Amz-Signature";
            public const string XAmzAlgorithm = "X-Amz-Algorithm";
            public const string XAmzCredential = "X-Amz-Credential";
            public const string XAmzTrailerHeader = "X-Amz-Trailer";

            public const string XAmzSSECustomerAlgorithmHeader = "x-amz-server-side-encryption-customer-algorithm";
            public const string XAmzSSECustomerKeyHeader = "x-amz-server-side-encryption-customer-key";
            public const string XAmzSSECustomerKeyMD5Header = "x-amz-server-side-encryption-customer-key-MD5";

            public const string XAmzCopySourceSSECustomerAlgorithmHeader = "x-amz-copy-source-server-side-encryption-customer-algorithm";
            public const string XAmzCopySourceSSECustomerKeyHeader = "x-amz-copy-source-server-side-encryption-customer-key";
            public const string XAmzCopySourceSSECustomerKeyMD5Header = "x-amz-copy-source-server-side-encryption-customer-key-MD5";

            public const string XAmzStorageClassHeader = "x-amz-storage-class";
            public const string XAmzWebsiteRedirectLocationHeader = "x-amz-website-redirect-location";
            public const string XAmzContentLengthHeader = "x-amz-content-length";
            public const string XAmzAclHeader = "x-amz-acl";
            public const string XAmzCopySourceHeader = "x-amz-copy-source";
            public const string XAmzCopySourceRangeHeader = "x-amz-copy-source-range";
            public const string XAmzCopySourceIfMatchHeader = "x-amz-copy-source-if-match";
            public const string XAmzCopySourceIfModifiedSinceHeader = "x-amz-copy-source-if-modified-since";
            public const string XAmzCopySourceIfNoneMatchHeader = "x-amz-copy-source-if-none-match";
            public const string XAmzCopySourceIfUnmodifiedSinceHeader = "x-amz-copy-source-if-unmodified-since";
            public const string XAmzMetadataDirectiveHeader = "x-amz-metadata-directive";
            public const string XAmzMfaHeader = "x-amz-mfa";
            public const string XAmzVersionIdHeader = "x-amz-version-id";
            public const string XAmzUserAgentHeader = "x-amz-user-agent";
            public const string XAmzAbortDateHeader = "x-amz-abort-date";
            public const string XAmzAbortRuleIdHeader = "x-amz-abort-rule-id";
            public const string XAmznTraceIdHeader = "x-amzn-trace-id";

            public const string XAwsEc2MetadataTokenTtlSeconds = "x-aws-ec2-metadata-token-ttl-seconds";
            public const string XAwsEc2MetadataToken = "x-aws-ec2-metadata-token";

            public const string AmzSdkInvocationId = "amz-sdk-invocation-id";
            public const string AmzSdkRequest = "amz-sdk-request";
        }

        #region hashAlgorithm

        [ThreadStatic]
        private static SHA256 _hashAlgorithm = null;
        private static SHA256 SHA256HashAlgorithmInstance
        {
            get
            {
                if (null == _hashAlgorithm)
                {
                    _hashAlgorithm = SHA256.Create();//SHA256.Create();
                }
                return _hashAlgorithm;
            }
        }


        /// <summary>
        /// Computes a SHA256 hash
        /// </summary>
        /// <param name="data">Input to compute the hash code for</param>
        /// <returns>Computed hash code</returns>
        public static byte[] ComputeSHA256Hash(byte[] data)
        {
            return SHA256HashAlgorithmInstance.ComputeHash(data);
        }

        /// <summary>
        /// Computes the non-keyed hash of the supplied data
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] ComputeHash(byte[] data)
        {
            return ComputeSHA256Hash(data);
        }



        public static byte[] HMACSignBinary(byte[] data, byte[] key, SigningAlgorithm algorithmName)
        {
            if (key == null || key.Length == 0)
                throw new ArgumentNullException("key", "Please specify a Secret Signing Key.");

            if (data == null || data.Length == 0)
                throw new ArgumentNullException("data", "Please specify data to sign.");

            KeyedHashAlgorithm algorithm = KeyedHashAlgorithm.Create(algorithmName.ToString().ToUpper(CultureInfo.InvariantCulture));
            if (null == algorithm)
                throw new InvalidOperationException("Please specify a KeyedHashAlgorithm to use.");

            try
            {
                algorithm.Key = key;
                byte[] bytes = algorithm.ComputeHash(data);
                return bytes;
            }
            finally
            {
                algorithm.Clear();
            }
        }


        public static byte[] ComputeKeyedHash(SigningAlgorithm algorithm, byte[] key, byte[] data)
        {
            return HMACSignBinary(data, key, algorithm);
        }


        public static byte[] ComputeKeyedHash(SigningAlgorithm algorithm, byte[] key, string data)
        {
            return ComputeKeyedHash(algorithm, key, Encoding.UTF8.GetBytes(data));
        }


        #endregion

        #region Utils

        private const int DefaultMarshallerVersion = 2;
        private const string Slash = "/";
        private const string EncodedSlash = "%2F";
        private const char SlashChar = '/';


        private const string S3EndpointPattern = @"^(.+\.)?s3[.-]([a-z0-9-]+)\.";
        //s3-control has a similar pattern to s3-region host names, so we explicitly exclude it
        private const string S3ControlExlusionPattern = @"^(.+\.)?s3-control\.";

        private static readonly Regex S3EndpointRegex = new Regex(S3EndpointPattern, RegexOptions.Compiled);
        private static readonly Regex S3ControlExlusionRegex = new Regex(S3ControlExlusionPattern, RegexOptions.Compiled);

        public static string AWSSDKUtilsToHex(byte[] data, bool lowercase)
        {
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < data.Length; i++)
            {
                sb.Append(data[i].ToString(lowercase ? "x2" : "X2", CultureInfo.InvariantCulture));
            }

            return sb.ToString();
        }

        protected static string CanonicalizeQueryParameters(IEnumerable<KeyValuePair<string, string>> parameters)
        {
            return CanonicalizeQueryParameters(parameters, true);
        }
        protected static string CanonicalizeQueryParameters(
           IEnumerable<KeyValuePair<string, string>> parameters,
           bool uriEncodeParameters)
        {
            if (parameters == null)
                return string.Empty;

            var sortedParameters = parameters.OrderBy(kvp => kvp.Key, StringComparer.Ordinal).ToList();
            var canonicalQueryString = new StringBuilder();
            foreach (var param in sortedParameters)
            {
                var key = param.Key;
                var value = param.Value;

                if (canonicalQueryString.Length > 0)
                    canonicalQueryString.Append("&");
                if (uriEncodeParameters)
                {
                    if (string.IsNullOrEmpty(value))
                        canonicalQueryString.AppendFormat("{0}=", UrlEncode(key, false));
                    else
                        canonicalQueryString.AppendFormat("{0}={1}", UrlEncode(key, false), UrlEncode(value, false));
                }
                else
                {
                    if (string.IsNullOrEmpty(value))
                        canonicalQueryString.AppendFormat("{0}=", key);
                    else
                        canonicalQueryString.AppendFormat("{0}={1}", key, value);
                }
            }

            return canonicalQueryString.ToString();
        }


        public static string CanonicalizeResourcePath(Uri endpoint, string resourcePath)
        {
            // This overload is kept for backward compatibility in existing code bases.
            return CanonicalizeResourcePath(endpoint, resourcePath, false, null, DefaultMarshallerVersion);
        }

        public static string CanonicalizeResourcePath(Uri endpoint, string resourcePath, bool detectPreEncode, IDictionary<string, string> pathResources, int marshallerVersion)
        {
            if (endpoint != null)
            {
                var path = endpoint.AbsolutePath;
                if (string.IsNullOrEmpty(path) || string.Equals(path, Slash, StringComparison.Ordinal))
                    path = string.Empty;

                if (!string.IsNullOrEmpty(resourcePath) && resourcePath.StartsWith(Slash, StringComparison.Ordinal))
                    resourcePath = resourcePath.Substring(1);

                if (!string.IsNullOrEmpty(resourcePath))
                    path = path + Slash + resourcePath;

                resourcePath = path;
            }

            if (string.IsNullOrEmpty(resourcePath))
                return Slash;

            IEnumerable<string> encodedSegments = SplitResourcePathIntoSegments(resourcePath, pathResources);

            var pathWasPreEncoded = false;
            if (detectPreEncode)
            {
                if (endpoint == null)
                    throw new ArgumentNullException(nameof(endpoint), "A non-null endpoint is necessary to decide whether or not to pre URL encode.");

                // S3 is a special case.  For S3 skip the pre encode.
                // For everything else URL pre encode the resource path segments.
                if (!IsS3Uri(endpoint))
                {
                    encodedSegments = encodedSegments.Select(segment => UrlEncode(segment, true).Replace(Slash, EncodedSlash));

                    pathWasPreEncoded = true;
                }
            }

            var canonicalizedResourcePath = JoinResourcePathSegments(encodedSegments, false);

            // Get the logger each time (it's cached) because we shouldn't store it in a static variable.
            //Logger.GetLogger(typeof(AWSSDKUtils)).DebugFormat("{0} encoded {1}{2} for canonicalization: {3}",
            //    pathWasPreEncoded ? "Double" : "Single",
            //    resourcePath,
            //    endpoint == null ? "" : " with endpoint " + endpoint.AbsoluteUri,
            //    canonicalizedResourcePath);

            return canonicalizedResourcePath;
        }




        public static bool IsS3Uri(Uri uri)
        {
            return S3EndpointRegex.Match(uri.Host).Success && !S3ControlExlusionRegex.Match(uri.Host).Success;
        }


        public static string JoinResourcePathSegments(IEnumerable<string> pathSegments, bool path)
        {
            // Encode for canonicalization
            pathSegments = pathSegments.Select(segment => UrlEncode(segment, path));

            if (path)
            {
                pathSegments = pathSegments.Select(segment => segment.Replace(Slash, EncodedSlash));
            }

            // join the encoded segments with /
            return string.Join(Slash, pathSegments.ToArray());
        }


        public static string CompressSpaces(string data)
        {
            if (data == null)
            {
                return null;
            }

            if (data.Length == 0)
            {
                return string.Empty;
            }

            var stringBuilder = new StringBuilder();
            var isWhiteSpace = false;
            foreach (var character in data)
            {
                if (!isWhiteSpace | !(isWhiteSpace = char.IsWhiteSpace(character)))
                {
                    stringBuilder.Append(isWhiteSpace ? ' ' : character);
                }
            }
            return stringBuilder.ToString();
        }

        public static IEnumerable<string> SplitResourcePathIntoSegments(string resourcePath, IDictionary<string, string> pathResources)
        {
            var splitChars = new char[] { SlashChar };
            var pathSegments = resourcePath.Split(splitChars, StringSplitOptions.None);
            if (pathResources == null || pathResources.Count == 0)
            {
                return pathSegments;
            }

            //Otherwise there are key/values that need to be resolved
            var resolvedSegments = new List<string>();
            foreach (var segment in pathSegments)
            {
                if (!pathResources.ContainsKey(segment))
                {
                    resolvedSegments.Add(segment);
                    continue;
                }

                //Determine if the path is greedy. If greedy the segment will be split at each / into multiple segments.
                if (segment.EndsWith("+}", StringComparison.Ordinal))
                {
                    resolvedSegments.AddRange(pathResources[segment].Split(splitChars, StringSplitOptions.None));
                }
                else
                {
                    resolvedSegments.Add(pathResources[segment]);
                }
            }

            return resolvedSegments;
        }


        public static string UrlEncode(string data, bool path)
        {
            return UrlEncode(3986, data, path);
        }



        public const string ValidUrlCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
        public const string ValidUrlCharactersRFC1738 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.";
        private static string ValidPathCharacters = DetermineValidPathCharacters();

        private static string DetermineValidPathCharacters()
        {
            const string basePathCharacters = "/:'()!*[]$";

            var sb = new StringBuilder();
            foreach (var c in basePathCharacters)
            {
                var escaped = Uri.EscapeUriString(c.ToString());
                if (escaped.Length == 1 && escaped[0] == c)
                    sb.Append(c);
            }
            return sb.ToString();
        }


        internal static Dictionary<int, string> RFCEncodingSchemes = new Dictionary<int, string>
        {
            { 3986,  ValidUrlCharacters },
            { 1738,  ValidUrlCharactersRFC1738 }
        };

        public static string UrlEncode(int rfcNumber, string data, bool path)
        {
            StringBuilder encoded = new StringBuilder(data.Length * 2);
            string validUrlCharacters;
            if (!RFCEncodingSchemes.TryGetValue(rfcNumber, out validUrlCharacters))
                validUrlCharacters = ValidUrlCharacters;

            string unreservedChars = String.Concat(validUrlCharacters, (path ? ValidPathCharacters : ""));

            foreach (char symbol in System.Text.Encoding.UTF8.GetBytes(data))
            {
                if (unreservedChars.IndexOf(symbol) != -1)
                {
                    encoded.Append(symbol);
                }
                else
                {
                    encoded.Append("%").Append(string.Format(CultureInfo.InvariantCulture, "{0:X2}", (int) symbol));
                }
            }

            return encoded.ToString();
        }
        #endregion
    }
}
