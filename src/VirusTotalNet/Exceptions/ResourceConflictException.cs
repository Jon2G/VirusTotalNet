using System;

namespace VirusTotalNet.Exceptions
{
    public class ResourceConflictException : Exception
    {
        public ResourceConflictException(string message) : base(message) { }
    }
}
