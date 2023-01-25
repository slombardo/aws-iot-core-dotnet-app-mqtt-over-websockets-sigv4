using System;
using System.Threading.Tasks;
using awsiotmqttoverwebsocketswinapp.View;
using awsiotmqttoverwebsocketswinapp.Model;
using MQTTnet.Client;
using MQTTnet;
using awsiotmqttoverwebsocketswinapp.Utils;
using System.Text;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using MQTTnet.Protocol;
using MQTTnet.Extensions.WebSocket4Net;
using OpenSSL.X509Certificate2Provider;

namespace awsiotmqttoverwebsocketswinapp.Presenter
{
    public class AwsIotPresenter
    {
        private readonly IAwsIotView view;

        public IMqttClient mqttClient;
        private MqttClientOptions mqttClientOptions;
        private string lastSubscribedTopic;
        private static RootCertificateTrust rootCertificateTrust;
        private static string certificateAuthorityCertPEMString;
        private static string deviceCertPEMString;
        private static string devicePrivateCertPEMString;


        public AwsIotPresenter(IAwsIotView view)
        {
            this.view = view;
        }

        public Func<Task> Reconnect
        {
            get;
            set;
        }

        public async Task ConnectToAwsIoTWithCertificates()
        {
            try
            {
                Reconnect = ConnectToAwsIoTWithCertificates;
                // Create a new MQTT client.
                var factory = new MqttFactory();
                mqttClient = factory.CreateMqttClient();
                mqttClient.ConnectedAsync += async e => await MqttClient_Connected(e);
                mqttClient.ApplicationMessageReceivedAsync += MqttClient_ApplicationMessageReceived;

                var broker = view.HostText;
                var port = int.Parse(view.Port);

                deviceCertPEMString = File.ReadAllText(view.CertificatePemPath);
                devicePrivateCertPEMString = File.ReadAllText(view.PrivatePemPath);
                certificateAuthorityCertPEMString = File.ReadAllText(view.AmazonRootPemPath);

                ICertificateProvider provider = new CertificateFromFileProvider(
                    deviceCertPEMString, devicePrivateCertPEMString, true);
                X509Certificate2 deviceCertificate = provider.Certificate;

                //Converting from PEM to X509 certs in C# is hard
                //Load the CA certificate
                //https://gist.github.com/ChrisTowles/f8a5358a29aebcc23316605dd869e839
                var certBytes = Encoding.UTF8.GetBytes(certificateAuthorityCertPEMString);
                var signingcert = new X509Certificate2(certBytes);

                //This is a helper class to allow verifying a root CA separately from the Windows root store
                rootCertificateTrust = new RootCertificateTrust();
                rootCertificateTrust.AddCert(signingcert);

                // Certificate based authentication
                List<X509Certificate> certs = new List<X509Certificate>
                {
                    signingcert,
                    deviceCertificate
                };

                MqttClientOptionsBuilderTlsParameters tlsOptions = new MqttClientOptionsBuilderTlsParameters();
                tlsOptions.Certificates = certs;
                tlsOptions.SslProtocol = System.Security.Authentication.SslProtocols.Tls12;
                tlsOptions.UseTls = true;
                tlsOptions.AllowUntrustedCertificates = true;
                tlsOptions.CertificateValidationHandler += rootCertificateTrust.VerifyServerCertificate;

                AwsMqttConnection awsMqttConnection = new AwsMqttConnection
                {
                    Host = view.HostText,
                    Region = view.RegionText,
                };

                string signedRequestUrl = awsMqttConnection.SignRequestUrl();

                //Set things up for our MQTTNet client
                //NOTE: AWS does NOT support will topics or retained messages
                //If you attempt to use either, it will disconnect with little explanation
                var options = new MqttClientOptionsBuilder()
                    .WithTcpServer(broker, port)
                    .WithClientId("mqttnet-ID")
                    .WithTls(tlsOptions)
                    .WithWebSocketServer(signedRequestUrl)
                    .Build();

                await mqttClient.ConnectAsync(options, CancellationToken.None);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex.Message);
            }

        }

        public async Task ConnectToAwsIoT()
        {
            Reconnect = ConnectToAwsIoT;

            try
            {
                AwsMqttConnection awsMqttConnection = new AwsMqttConnection
                {
                    Host = view.HostText,
                    Region = view.RegionText,
                    AccessKey = view.AccessKeyText,
                    SecretKey = view.SecretKeyText
                };

                string signedRequestUrl = awsMqttConnection.SignRequestUrl();

                var factory = new MqttFactory().UseWebSocket4Net();
                mqttClient = factory.CreateMqttClient();
                mqttClient.ConnectedAsync += async e => await MqttClient_Connected(e) ;
                mqttClient.ApplicationMessageReceivedAsync += MqttClient_ApplicationMessageReceived;

                mqttClientOptions = new MqttClientOptionsBuilder()
                        .WithWebSocketServer(signedRequestUrl)
                        .Build();

                await mqttClient.ConnectAsync(mqttClientOptions);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex.Message);
            }
        }

        private Task MqttClient_Connected(MqttClientConnectedEventArgs e)
        {
            view.ConnectStatusLabel = "Connected";
            Logger.LogInfo($"MQTT Client: Connected with result: {e.ConnectResult.ResultCode}");
            return Task.CompletedTask;
        }

        public async Task PublishMessage(string message, string topic)
        {
            try
            {
                var mqttMessage = new MqttApplicationMessageBuilder()
                    .WithTopic(topic)
                    .WithPayload(message)
                    .WithQualityOfServiceLevel(MqttQualityOfServiceLevel.AtLeastOnce)
                    .Build();

                await mqttClient.PublishAsync(mqttMessage, CancellationToken.None);
                Logger.LogInfo($"Published message: {message}");
            }
            catch (Exception ex)
            {
                Logger.LogError(ex.Message);
            }
        }

        public async Task SubscribeTo(string topic)
        {
            try
            {
                if (lastSubscribedTopic != topic)
                {
                    if (lastSubscribedTopic != null)
                        await mqttClient.UnsubscribeAsync(lastSubscribedTopic);

                    await mqttClient.SubscribeAsync(topic);
                    Logger.LogInfo($"Subscribed to: {topic}");
                    lastSubscribedTopic = topic;

                    view.SubscribeStatusLabel = $"Subscribed to {topic}";
                }
                else
                {
                    Logger.LogInfo($"Already subscribed to: {topic}");
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(ex.Message);
            }
        }

        private Task MqttClient_ApplicationMessageReceived(MqttApplicationMessageReceivedEventArgs e)
        {
            StringBuilder stringBuilder = new StringBuilder();
            string payload = Encoding.UTF8.GetString(e.ApplicationMessage.Payload, 0, e.ApplicationMessage.Payload.Length);

            stringBuilder.AppendLine("### RECEIVED APPLICATION MESSAGE ###");
            stringBuilder.AppendLine("Topic: " + e.ApplicationMessage.Topic);
            stringBuilder.AppendLine("Payload: " + payload);
            stringBuilder.AppendLine("QOS: " + e.ApplicationMessage.QualityOfServiceLevel);
            stringBuilder.AppendLine("QOS Retain: " + e.ApplicationMessage.Retain);
            stringBuilder.AppendLine();
            
            view.ReceivedMessageText = stringBuilder.ToString();
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Verifies certificates against a list of manually trusted certs.
    /// If a certificate is not in the Windows cert store, this will check that it's valid per our internal code.
    /// </summary>
    internal class RootCertificateTrust
    {

        X509Certificate2Collection certificates;
        internal RootCertificateTrust()
        {
            certificates = new X509Certificate2Collection();
        }

        /// <summary>
        /// Add a trusted certificate
        /// </summary>
        /// <param name="x509Certificate2"></param>
        internal void AddCert(X509Certificate2 x509Certificate2)
        {
            certificates.Add(x509Certificate2);
        }

        /// <summary>
        /// This matches the delegate signature expected for certificate verification for MQTTNet
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        internal bool VerifyServerCertificate(MqttClientCertificateValidationEventArgs arg) => VerifyServerCertificate(new object(), arg.Certificate, arg.Chain, arg.SslPolicyErrors);


        /// <summary>
        /// This matches the delegate signature expected for certificate verification for M2MQTT
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="certificate"></param>
        /// <param name="chain"></param>
        /// <param name="sslPolicyErrors"></param>
        /// <returns></returns>
        internal bool VerifyServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {

            if (sslPolicyErrors == SslPolicyErrors.None) return true;

            X509Chain chainNew = new X509Chain();
            var chainTest = chain;

            chainTest.ChainPolicy.ExtraStore.AddRange(certificates);

            // Check all properties
            chainTest.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            // This setup does not have revocation information
            chainTest.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            // Build the chain
            var buildResult = chainTest.Build(new X509Certificate2(certificate));

            //Just in case it built with trust
            if (buildResult) return true;

            //If the error is something other than UntrustedRoot, fail
            foreach (var status in chainTest.ChainStatus)
            {
                if (status.Status != X509ChainStatusFlags.UntrustedRoot)
                {
                    return false;
                }
            }

            //If the UntrustedRoot is on something OTHER than the GreenGrass CA, fail
            foreach (var chainElement in chainTest.ChainElements)
            {
                foreach (var chainStatus in chainElement.ChainElementStatus)
                {
                    if (chainStatus.Status == X509ChainStatusFlags.UntrustedRoot)
                    {
                        var found = certificates.Find(X509FindType.FindByThumbprint, chainElement.Certificate.Thumbprint, false);
                        if (found.Count == 0) return false;
                    }
                }
            }

            return true;
        }

    }
}
