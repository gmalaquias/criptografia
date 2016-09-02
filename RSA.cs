using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Vendor
{
    public class RSA
    {
        RSACryptoServiceProvider generatorKeys = null;

        public RSA(int bits)
        {
            generatorKeys = new RSACryptoServiceProvider(bits);
        }

        public static string keyToString(RSAParameters key)
        {
            //precisamos de um buffer
            var sw = new System.IO.StringWriter();
            //serializador
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            //serializa a chave em um buffer
            xs.Serialize(sw, key);
            //resgata a string do buffer
            return sw.ToString();
        }

        public static RSAParameters stringToRSA(string key)
        {
            var sr = new System.IO.StringReader(key);
            //serializador
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            //resgata o objeto do stream
            return (RSAParameters)xs.Deserialize(sr);
        }

        public static string encrypt(string plainText, RSAParameters key, bool url = false)
        {
            using (var csp = new RSACryptoServiceProvider())
            {
                csp.ImportParameters(key);

                //convertemos em byte para usar na criptografia
                var bytesPlainTextData = System.Text.Encoding.Unicode.GetBytes(plainText);

                //cifra o texto
                var bytesCypherText = csp.Encrypt(bytesPlainTextData, false);

                //base64 para representar nossos bytes
                if (url)
                    return Convert.ToBase64String(bytesCypherText).Replace("+", "**");

                return Convert.ToBase64String(bytesCypherText);
            }
        }

        public static string decrypt(string cypherText, RSAParameters key, bool url = false)
        {

            using (var csp = new RSACryptoServiceProvider())
            {
                if (url)
                    cypherText = cypherText.Replace("**", "+");

                csp.ImportParameters(key);

                //primeiro, resgatar o valor em bytes
                var bytesCypherText = Convert.FromBase64String(cypherText);

                //resgata o texto em claro em bytes
                var bytesPlainTextData = csp.Decrypt(bytesCypherText, false);

                //converte o texto em bytes para em claro
                return System.Text.Encoding.Unicode.GetString(bytesPlainTextData);
            }
        }


        public RSAParameters generateKey(bool isPrivateKey)
        {
            return this.generatorKeys.ExportParameters(isPrivateKey);
        }

    }
}



