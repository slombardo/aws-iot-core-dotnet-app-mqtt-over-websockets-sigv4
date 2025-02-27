﻿using System;
using System.Collections.Generic;
using awsiotmqttoverwebsocketswinapp.Signers;

namespace awsiotmqttoverwebsocketswinapp.Model
{
    public class AwsMqttConnection
    {
        public string Host { get; set; }
        public string Region { get; set; }
        public string AccessKey { get; set; }
        public string SecretKey { get; set; }

        public string SignRequestUrl()
        {
            var endpointBuilder = new UriBuilder("wss", Host, 443, "mqtt");

            var signer = new AWS4SignerForQueryParameterAuth
            {
                EndpointUri = endpointBuilder.Uri,
                HttpMethod = "GET",
                Service = "iotdevicegateway",
                Region = Region
            };

            var headers = new Dictionary<string, string>();

            var authorization = signer.ComputeSignature(headers,
                                                        string.Empty,
                                                        AWS4SignerBase.EMPTY_BODY_SHA256,
                                                        this.AccessKey,
                                                        this.SecretKey);

            var signedRequestBuilder = new UriBuilder(endpointBuilder.Uri)
            {
                Query = authorization
            };

            return $"{signedRequestBuilder.Uri.Host}{signedRequestBuilder.Uri.PathAndQuery}";
            return signedRequestBuilder.Uri.AbsoluteUri;
        }
    }
}