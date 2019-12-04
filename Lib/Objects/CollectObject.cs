// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System.Reflection;

namespace AttackSurfaceAnalyzer.Objects
{
    public abstract class CollectObject
    {
        public RESULT_TYPE ResultType { get; set; }
        public abstract string Identity { get; }
        public string Hash
        {
            get
            {
                return CryptoHelpers.CreateHash(JsonConvert.SerializeObject(this, new JsonSerializerSettings()
                {
                    Formatting = Formatting.Indented,
                    NullValueHandling = NullValueHandling.Ignore,
                    DefaultValueHandling = DefaultValueHandling.Ignore,
                    ContractResolver = new DefaultCollectObjectContractResolver()
                }));
            }
        }
        public int Id { get; set; }
        public string RunId { get; set; }

        private class DefaultCollectObjectContractResolver : DefaultContractResolver
        {
            public static readonly DefaultCollectObjectContractResolver Instance = new DefaultCollectObjectContractResolver();

            protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
            {
                JsonProperty property = base.CreateProperty(member, memberSerialization);

                if (property.DeclaringType == typeof(CollectObject))
                {
                    if (property.PropertyName == "Hash")
                    {
                        property.ShouldSerialize = _ => { return false; };
                    }
                }

                return property;
            }
        }
    }
}
