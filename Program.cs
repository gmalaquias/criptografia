using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Vendor;

namespace Criptografia
{
    public class Program
    {
        public void Main(string[] args)
        {

            //RSA Example

            RSA generator = new RSA(2048); //2048 bits

            var key_private = generator.generateKey(true);

            var key_public = generator.generateKey(false);



        }
    }
}
