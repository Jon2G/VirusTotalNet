using System;

namespace VirusTotalNet.Exceptions
{
    internal class ResourceNotFoundException : Exception
    {
        public ResourceNotFoundException(string message) : base(message) { }
    }
}
