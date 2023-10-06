using BoletoHibridoBradesco.Security;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace BoletoHibridoBradesco
{
    internal class Program
    {
        #region Private Fields

        private static HttpClient client;

        #endregion Private Fields

        #region Private Methods

        /// <summary>
        /// Cria um boleto
        /// </summary>
        /// <param name="token">Token de acesso</param>
        /// <param name="assertion">"assertion" criada anteriormente</param>
        /// <param name="certificate">Certificado</param>
        /// <returns></returns>
        /// <exception cref="Exception">Exceções gerais</exception>
        private static async Task CreateBilletAsync(string token, SignedAssertion assertion, X509Certificate2 certificate)
        {
            //Este json é/foi fornecido pelo suporte Bradesco.
            var json = "{\"ctitloCobrCdent\":\"11122233346\",\"registrarTitulo\":\"1\"," +
                       "\"codUsuario\":\"APISERVIC\",\"nroCpfCnpjBenef\":\"86342625\"," +
                       "\"filCpfCnpjBenef\":\"0001\",\"digCpfCnpjBenef\":\"57\"," +
                       "\"tipoAcesso\":\"2\",\"cpssoaJuridContr\":\"2337627\"," +
                       "\"ctpoContrNegoc\":\"000\",\"nseqContrNegoc\":\"2337627\"," +
                       "\"cidtfdProdCobr\":\"09\",\"cnegocCobr\":\"387700000000060550\"," +
                       "\"filler\":\"\",\"codigoBanco\":\"237\",\"eNseqContrNegoc\":\"2337627\"," +
                       "\"tipoRegistro\":\"001\",\"cprodtServcOper\":\"00000000\"," +
                       "\"ctitloCliCdent\":\"999665-1-1\",\"demisTitloCobr\":\"17.07.2023\"," +
                       "\"dvctoTitloCobr\":\"18.07.2023\",\"cidtfdTpoVcto\":\"0\"," +
                       "\"cindcdEconmMoeda\":\"00006\",\"vnmnalTitloCobr\":\"5000\"," +
                       "\"qmoedaNegocTitlo\":\"0\",\"cespceTitloCobr\":\"02\",\"cindcdAceitSacdo\":\"N\"," +
                       "\"ctpoProteTitlo\":\"00\",\"ctpoPrzProte\":\"00\",\"ctpoProteDecurs\":\"00\"," +
                       "\"ctpoPrzDecurs\":\"00\",\"cctrlPartcTitlo\":\"00811927249996650001\"," +
                       "\"cformaEmisPplta\":\"02\",\"cindcdPgtoParcial\":\"N\"," +
                       "\"qtdePgtoParcial\":\"000\",\"filler1\":\"\",\"ptxJuroVcto\":\"0\"," +
                       "\"vdiaJuroMora\":\"00000000000000012\",\"qdiaInicJuro\":\"01\"," +
                       "\"pmultaAplicVcto\":\"000000\",\"vmultaAtrsoPgto\":\"100\",\"qdiaInicMulta\":\"01\"," +
                       "\"pdescBonifPgto01\":\"0\",\"vdescBonifPgto01\":\"0\",\"dlimDescBonif1\":\"\"," +
                       "\"pdescBonifPgto02\":\"0\",\"vdescBonifPgto02\":\"0\",\"dlimDescBonif2\":\"\"," +
                       "\"pdescBonifPgto03\":\"0\",\"vdescBonifPgto03\":\"0\",\"dlimDescBonif3\":\"\"," +
                       "\"ctpoPrzCobr\":\"01\",\"pdescBonifPgto\":\"0\",\"vdescBonifPgto\":\"1000\"," +
                       "\"dlimBonifPgto\":\"18.07.2023\",\"vabtmtTitloCobr\":\"00000000000000000\"," +
                       "\"viofPgtoTitlo\":\"0\",\"filler2\":\"\",\"isacdoTitloCobr\":\"FULANOSOUZA\"," +
                       "\"elogdrSacdoTitlo\":\"RUAFULANOCICRANO250\",\"enroLogdrSacdo\":\"11\"," +
                       "\"ecomplLogdrSacdo\":\"\",\"ccepSacdoTitlo\":\"00000\",\"ccomplCepSacdo\":\"160\"," +
                       "\"ebairoLogdrSacdo\":\"CENTRO\",\"imunSacdoTitlo\":\"CIDADEX\",\"csglUfSacdo\":\"PR\"," +
                       "\"indCpfCnpjSacdo\":\"1\",\"nroCpfCnpjSacdo\":\"12345678911\"," +
                       "\"renderEletrSacdo\":\"test@example.com\",\"cdddFoneSacdo\":\"000\"," +
                       "\"cfoneSacdoTitlo\":\"00000000\",\"bancoDeb\":\"000\",\"agenciaDeb\":\"00000\"," +
                       "\"agenciaDebDv\":\"0\",\"contaDeb\":\"0000000000000\",\"bancoCentProt\":\"000\"," +
                       "\"agenciaDvCentPr\":\"00000\",\"isacdrAvalsTitlo\":\"\",\"elogdrSacdrAvals\":\"\"," +
                       "\"enroLogdrSacdr\":\"\",\"ecomplLogdrSacdr\":\"\",\"ccepSacdrTitlo\":\"00000\"," +
                       "\"ccomplCepSacdr\":\"000\",\"ebairoLogdrSacdr\":\"\",\"imunSacdrAvals\":\"\"," +
                       "\"csglUfSacdr\":\"\",\"indCpfCnpjSacdr\":\"\",\"nroCpfCnpjSacdr\":\"00000000000000\"," +
                       "\"renderEletrSacdr\":\"\",\"cdddFoneSacdr\":\"\",\"cfoneSacdrTitlo\":\"\",\"filler3\":\"\"," +
                       "\"fase\":\"1\",\"cindcdCobrMisto\":\"S\",\"ialiasAdsaoCta\":\"\",\"iconcPgtoSpi\":\"\"," +
                       "\"caliasAdsaoCta\":\"\",\"ilinkGeracQrcd\":\"\",\"wqrcdPdraoMercd\":\"\"," +
                       "\"validadeAposVencimento\":\"\",\"filler4\":\"\"}";

            //nonce, lembra da criação do "assertion"?
            var nonce = assertion.Jti;

            //O cabeçalho X-Brad-Signature precisa do json do boleto
            var xBrad = Signer.CreateXBradSignature(token, assertion.Timestamp, json, nonce, certificate);

            //prepara os headers
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("X-Brad-Signature", xBrad);//criada e assinada anteriormente
            client.DefaultRequestHeaders.Add("X-Brad-Nonce", nonce.ToString()); //jti criado no momento do "assertion"
            client.DefaultRequestHeaders.Add("X-Brad-Timestamp", assertion.Timestamp); // timestamp criado no momento do "assertion"
            client.DefaultRequestHeaders.Add("X-Brad-Algorithm", "SHA256");
            client.DefaultRequestHeaders.Add("Authorization", token); // token solicitado no serviço de autenticação do Bradesco

            //conteúdo
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            //Registrar o boleto
            var response = await client.PostAsync("https://proxy.api.prebanco.com.br/v1/boleto-hibrido/registrar-boleto", content);
            json = await response.Content.ReadAsStringAsync();

            //Se tudo correu bem, é um sucesso e o boleto foi registrado
            if(!response.IsSuccessStatusCode)
            {
                //Xii! Deu erro
                throw new Exception(json);
            }

            Console.WriteLine("O boleto foi gerado com sucesso.");
        }

        /// <summary>
        /// Gera um token e retorna
        /// </summary>
        /// <param name="clientId">Client_Id obtido junto ao banco Bradesco</param>
        /// <param name="certificate">Certificado enviado ao Bradesco para obtenção do Client_Id</param>
        /// <returns></returns>
        /// <exception cref="Exception">Exceção genérica</exception>
        private static async Task<(SignedAssertion Assertion, string Token)> GetTokenAsync(string clientId, X509Certificate2 certificate)
        {
            // Assinar e criar o Assertion, necessário para a solicitação do token do Bradesco
            var assertion = Signer.CreateAssertion(clientId, certificate);

            //Criar o http client para a requisição do token
            var serviceProvider = new ServiceCollection().AddHttpClient().BuildServiceProvider();
            var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
            client = httpClientFactory.CreateClient(nameof(BoletoHibridoBradesco));

            //prepara os headers
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Connection.Add("keep-alive");
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));

            //conteúdo
            var content = new FormUrlEncodedContent(new[]
            {
                KeyValuePair.Create("grant_type","urn:ietf:params:oauth:grant-type:jwt-bearer"),
                KeyValuePair.Create("assertion",assertion.Assertion)
            });

            //Buscar o token
            var response = await client.PostAsync("https://proxy.api.prebanco.com.br/auth/server/v1.2/token", content);
            var json = await response.Content.ReadAsStringAsync();

            //Se tudo correu bem, é um sucesso e o token foi gerado
            if(response.IsSuccessStatusCode)
            {
                var token = JsonConvert.DeserializeObject<JToken>(json)["access_token"].ToString();
                return (assertion, token);
            }

            //Xii! Deu erro
            throw new Exception(json);
        }

        private static void Main(string[] args)
        {
            ///Cliente Id Recebido do Bradesco
            var clientId = "<<client_Id>>";

            //Certificado enviado para o Bradesco para a criação do Client Id
            var certificate = new X509Certificate2(@"C:\Caminho_Certificado.pfx", "senha");

            Console.Title = "Boleto Hibrido Bradesco";
            Console.WriteLine("Olá, vamos emitir um boleto com QR Code!");
            MainAsync(clientId, certificate).Wait();
            Console.ReadKey();
        }

        private static async Task MainAsync(string clientId, X509Certificate2 certificate)
        {
            //Aqui, vamos buscar o token
            var token = await GetTokenAsync(clientId, certificate);

            //De posse do token, iremos criar o boleto.
            await CreateBilletAsync(token.Token, token.Assertion, certificate);
        }

        #endregion Private Methods
    }
}