using BoletoHibridoBradesco.Helpers;
using Jose;
using Newtonsoft.Json;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace BoletoHibridoBradesco.Security
{
    /// <summary>
    /// Classe de apoio para geração e assinatura Bradesco
    /// </summary>
    public abstract class Signer
    {
        #region Public Methods

        public static string ComputeSHA256(string value, X509Certificate2 certificate)
        {
            using var rsa = certificate.GetRSAPrivateKey();
            var data = Encoding.ASCII.GetBytes(value);
            var signedData = Convert.ToBase64String(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            return signedData;
        }

        /// <summary>
        /// Cria as afirmações JWT e as assina com base no certificado.
        /// </summary>
        /// <param name="clientId">Client_Id recebido do Bradesco</param>
        /// <param name="certificate">Certificado A1</param>
        /// <returns></returns>
        public static SignedAssertion CreateAssertion(string clientId, X509Certificate2 certificate)
        {
            //Gera a Assertion do tópico 3.7 do manual Nov.2022 - Api_Registro_Titulo_Cobranca_QR Code_Bradesco_v1.pdf
            var dt = DateTime.UtcNow;
            var timestamp = $"{dt:yyyy-MM-ddTHH:mm:ss}-00:00";
            var iat = UnixEpochHelper.GetSecondsSince(dt);
            var jti = long.Parse($"{UnixEpochHelper.GetSecondsSince(dt)}000");
            var exp = UnixEpochHelper.GetSecondsSince(dt.AddHours(1));
            var assertion = SignToken(new
            {
                aud = "https://proxy.api.prebanco.com.br/auth/server/v1.1/token",// (audience): destinatário do token, quem vai usar?
                sub = $"{clientId}",//assunto
                iat, //(issued at): timestamp de quando o token foi criado;
                jti, // nonce - numérico de no máximo dezoito dígitos, valor sem repetição. o NONCE é uma valor aleatório que só pode ser usado uma única vez
                exp, // (expiration): timestamp de quando o token irá expirar
                ver = "1.1" //versão
            }, certificate);

            return (assertion, timestamp, iat, jti, exp);
        }

        /// <summary>
        /// Assina o cabeçalho X-Brad-Signature, que deve ser enviado durante as requisições com as APIs Bradesco
        /// </summary>
        /// <param name="accessToken">Token de acesso obtido anteriormente por serviço de auntenticação/autorização do Bradesco</param>
        /// <param name="certificate">Certificado. O mesmo usado para a criação do Client_Id</param>
        /// <param name="json">Json do boleto que será enviado para a emissão</param>
        /// <param name="nonce">Número único e aleatório. O mesmo usado na criação do assertion. Veja <see cref="CreateAssertion(string, X509Certificate2)"/></param>
        /// <param name="timestamp">Timestamp. O mesmo usado na criação do assertion. Veja <see cref="CreateAssertion(string, X509Certificate2)"/></param>
        /// <returns></returns>
        public static string CreateXBradSignature(string accessToken, string timestamp, string json, long nonce, X509Certificate2 certificate)
        {
            var sb = new StringBuilder();
            sb.Append("POST\n"); // Método HTTP usado na requisição
            sb.Append($"/v1/boleto-hibrido/registrar-boleto\n"); // Endpoint da chamada
            sb.Append('\n'); // Query Parameters caso existam
            sb.Append($"{json}\n"); // Body da requisição ou deixar uma linha em branco nos casos em que não existe body
            sb.Append($"{accessToken}\n"); // Token de acesso gerado anteriormente
            sb.Append($"{nonce}\n"); // Nonce (Jti) gerado no momento do "assertion"
            sb.Append($"{timestamp}\n"); // Timestamp representando o momento da chamada. Foi criado no mesmo instante do "assertion"
            sb.Append("SHA256"); // Algoritmo usado para assinar o JWT

            // faz a assinatura
            var signed = ComputeSHA256(sb.ToString(), certificate);

            // remove os =
            signed = signed.Replace("=", "");

            // troca o + por -
            signed = signed.Replace("+", "-");

            // troca / por _
            signed = signed.Replace("/", "_");

            // limpa os espaços das extremidades
            signed = signed.Trim();

            return signed;
        }

        /// <summary>
        /// Assina a mensagem e retorna o token assinado com o certificado
        /// </summary>
        /// <param name="message">Mensagem para assinar</param>
        /// <param name="certificate">Certificado</param>
        /// <returns></returns>
        public static string SignToken(object message, X509Certificate2 certificate)
        {
            var senderPrivateKey = certificate.GetRSAPrivateKey();
            var signed = JWT.Encode(message, senderPrivateKey, JwsAlgorithm.RS256, null);

            Debug.WriteLine(JsonConvert.SerializeObject(message, Formatting.Indented), "Message");
            Debug.WriteLine(signed, "Message Signed");

            return signed;
        }

        #endregion Public Methods
    }

    public record struct SignedAssertion(string Assertion, string Timestamp, long Iat, long Jti, long Exp)
    {
        public static implicit operator (string Assertion, string Timestamp, long Iat, long Jti, long Exp)(SignedAssertion value) => (value.Assertion, value.Timestamp, value.Iat, value.Jti, value.Exp);
        public static implicit operator SignedAssertion((string Assertion, string Timestamp, long Iat, long Jti, long Exp) value) => new(value.Assertion, value.Timestamp, value.Iat, value.Jti, value.Exp);
    }
}