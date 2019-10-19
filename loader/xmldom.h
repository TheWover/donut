/**
  BSD 3-Clause License

  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

  /**
    typedef struct IXMLDOMNodeVtbl {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IXMLDOMNode * This,
             REFIID riid,
              void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IXMLDOMNode * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IXMLDOMNode * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            IXMLDOMNode * This,
            UINT *pctinfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            IXMLDOMNode * This,
            UINT iTInfo,
            LCID lcid,
            ITypeInfo **ppTInfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            IXMLDOMNode * This,
             REFIID riid,
             LPOLESTR *rgszNames,
             UINT cNames,
             LCID lcid,
             DISPID *rgDispId);
        
         HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            IXMLDOMNode * This,
             DISPID dispIdMember,
             REFIID riid,
             LCID lcid,
             WORD wFlags,
             DISPPARAMS *pDispParams,
             VARIANT *pVarResult,
             EXCEPINFO *pExcepInfo,
             UINT *puArgErr);
        
         HRESULT ( STDMETHODCALLTYPE *get_nodeName )( 
            IXMLDOMNode * This,
             BSTR *name);
        
         HRESULT ( STDMETHODCALLTYPE *get_nodeValue )( 
            IXMLDOMNode * This,
             VARIANT *value);
        
         HRESULT ( STDMETHODCALLTYPE *put_nodeValue )( 
            IXMLDOMNode * This,
             VARIANT value);
        
         HRESULT ( STDMETHODCALLTYPE *get_nodeType )( 
            IXMLDOMNode * This,
             DOMNodeType *type);
        
         HRESULT ( STDMETHODCALLTYPE *get_parentNode )( 
            IXMLDOMNode * This,
             IXMLDOMNode **parent);
        
         HRESULT ( STDMETHODCALLTYPE *get_childNodes )( 
            IXMLDOMNode * This,
             IXMLDOMNodeList **childList);
        
         HRESULT ( STDMETHODCALLTYPE *get_firstChild )( 
            IXMLDOMNode * This,
             IXMLDOMNode **firstChild);
        
         HRESULT ( STDMETHODCALLTYPE *get_lastChild )( 
            IXMLDOMNode * This,
             IXMLDOMNode **lastChild);
        
         HRESULT ( STDMETHODCALLTYPE *get_previousSibling )( 
            IXMLDOMNode * This,
             IXMLDOMNode **previousSibling);
        
         HRESULT ( STDMETHODCALLTYPE *get_nextSibling )( 
            IXMLDOMNode * This,
             IXMLDOMNode **nextSibling);
        
         HRESULT ( STDMETHODCALLTYPE *get_attributes )( 
            IXMLDOMNode * This,
             IXMLDOMNamedNodeMap **attributeMap);
        
         HRESULT ( STDMETHODCALLTYPE *insertBefore )( 
            IXMLDOMNode * This,
             IXMLDOMNode *newChild,
             VARIANT refChild,
             IXMLDOMNode **outNewChild);
        
         HRESULT ( STDMETHODCALLTYPE *replaceChild )( 
            IXMLDOMNode * This,
             IXMLDOMNode *newChild,
             IXMLDOMNode *oldChild,
             IXMLDOMNode **outOldChild);
        
         HRESULT ( STDMETHODCALLTYPE *removeChild )( 
            IXMLDOMNode * This,
             IXMLDOMNode *childNode,
             IXMLDOMNode **oldChild);
        
         HRESULT ( STDMETHODCALLTYPE *appendChild )( 
            IXMLDOMNode * This,
             IXMLDOMNode *newChild,
             IXMLDOMNode **outNewChild);
        
         HRESULT ( STDMETHODCALLTYPE *hasChildNodes )( 
            IXMLDOMNode * This,
             VARIANT_BOOL *hasChild);
        
         HRESULT ( STDMETHODCALLTYPE *get_ownerDocument )( 
            IXMLDOMNode * This,
             IXMLDOMDocument **XMLDOMDocument);
        
         HRESULT ( STDMETHODCALLTYPE *cloneNode )( 
            IXMLDOMNode * This,
             VARIANT_BOOL deep,
             IXMLDOMNode **cloneRoot);
        
         HRESULT ( STDMETHODCALLTYPE *get_nodeTypeString )( 
            IXMLDOMNode * This,
             BSTR *nodeType);
        
         HRESULT ( STDMETHODCALLTYPE *get_text )( 
            IXMLDOMNode * This,
             BSTR *text);
        
         HRESULT ( STDMETHODCALLTYPE *put_text )( 
            IXMLDOMNode * This,
             BSTR text);
        
         HRESULT ( STDMETHODCALLTYPE *get_specified )( 
            IXMLDOMNode * This,
             VARIANT_BOOL *isSpecified);
        
         HRESULT ( STDMETHODCALLTYPE *get_definition )( 
            IXMLDOMNode * This,
             IXMLDOMNode **definitionNode);
        
         HRESULT ( STDMETHODCALLTYPE *get_nodeTypedValue )( 
            IXMLDOMNode * This,
             VARIANT *typedValue);
        
         HRESULT ( STDMETHODCALLTYPE *put_nodeTypedValue )( 
            IXMLDOMNode * This,
             VARIANT typedValue);
        
         HRESULT ( STDMETHODCALLTYPE *get_dataType )( 
            IXMLDOMNode * This,
             VARIANT *dataTypeName);
        
         HRESULT ( STDMETHODCALLTYPE *put_dataType )( 
            IXMLDOMNode * This,
             BSTR dataTypeName);
        
         HRESULT ( STDMETHODCALLTYPE *get_xml )( 
            IXMLDOMNode * This,
             BSTR *xmlString);
        
         HRESULT ( STDMETHODCALLTYPE *transformNode )( 
            IXMLDOMNode * This,
             IXMLDOMNode *stylesheet,
             BSTR *xmlString);
        
         HRESULT ( STDMETHODCALLTYPE *selectNodes )( 
            IXMLDOMNode * This,
             BSTR queryString,
             IXMLDOMNodeList **resultList);
        
         HRESULT ( STDMETHODCALLTYPE *selectSingleNode )( 
            IXMLDOMNode * This,
             BSTR queryString,
             IXMLDOMNode **resultNode);
        
         HRESULT ( STDMETHODCALLTYPE *get_parsed )( 
            IXMLDOMNode * This,
             VARIANT_BOOL *isParsed);
        
         HRESULT ( STDMETHODCALLTYPE *get_namespaceURI )( 
            IXMLDOMNode * This,
             BSTR *namespaceURI);
        
         HRESULT ( STDMETHODCALLTYPE *get_prefix )( 
            IXMLDOMNode * This,
             BSTR *prefixString);
        
         HRESULT ( STDMETHODCALLTYPE *get_baseName )( 
            IXMLDOMNode * This,
             BSTR *nameString);
        
         HRESULT ( STDMETHODCALLTYPE *transformNodeToObject )( 
            IXMLDOMNode * This,
             IXMLDOMNode *stylesheet,
             VARIANT outputObject);
        
        END_INTERFACE
    } IXMLDOMNodeVtbl;

    typedef struct _IXMLDOMNode {
        IXMLDOMNodeVtbl *lpVtbl;
    } XMLDOMNode;
    
    typedef struct IXMLDOMDocumentVtbl {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IXMLDOMDocument * This,
             REFIID riid,
             
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IXMLDOMDocument * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IXMLDOMDocument * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            IXMLDOMDocument * This,
             UINT *pctinfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            IXMLDOMDocument * This,
             UINT iTInfo,
             LCID lcid,
             ITypeInfo **ppTInfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            IXMLDOMDocument * This,
             REFIID riid,
             LPOLESTR *rgszNames,
             UINT cNames,
             LCID lcid,
             DISPID *rgDispId);
        
         HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            IXMLDOMDocument * This,
             DISPID dispIdMember,
             REFIID riid,
             LCID lcid,
             WORD wFlags,
             DISPPARAMS *pDispParams,
             VARIANT *pVarResult,
             EXCEPINFO *pExcepInfo,
             UINT *puArgErr);
        
         HRESULT ( STDMETHODCALLTYPE *get_nodeName )( 
            IXMLDOMDocument * This,
             BSTR *name);
        
         HRESULT ( STDMETHODCALLTYPE *get_nodeValue )( 
            IXMLDOMDocument * This,
             VARIANT *value);
        
         HRESULT ( STDMETHODCALLTYPE *put_nodeValue )( 
            IXMLDOMDocument * This,
             VARIANT value);
        
         HRESULT ( STDMETHODCALLTYPE *get_nodeType )( 
            IXMLDOMDocument * This,
             DOMNodeType *type);
        
         HRESULT ( STDMETHODCALLTYPE *get_parentNode )( 
            IXMLDOMDocument * This,
             IXMLDOMNode **parent);
        
         HRESULT ( STDMETHODCALLTYPE *get_childNodes )( 
            IXMLDOMDocument * This,
             IXMLDOMNodeList **childList);
        
         HRESULT ( STDMETHODCALLTYPE *get_firstChild )( 
            IXMLDOMDocument * This,
             IXMLDOMNode **firstChild);
        
         HRESULT ( STDMETHODCALLTYPE *get_lastChild )( 
            IXMLDOMDocument * This,
             IXMLDOMNode **lastChild);
        
         HRESULT ( STDMETHODCALLTYPE *get_previousSibling )( 
            IXMLDOMDocument * This,
             IXMLDOMNode **previousSibling);
        
         HRESULT ( STDMETHODCALLTYPE *get_nextSibling )( 
            IXMLDOMDocument * This,
             IXMLDOMNode **nextSibling);
        
         HRESULT ( STDMETHODCALLTYPE *get_attributes )( 
            IXMLDOMDocument * This,
             IXMLDOMNamedNodeMap **attributeMap);
        
         HRESULT ( STDMETHODCALLTYPE *insertBefore )( 
            IXMLDOMDocument * This,
             IXMLDOMNode *newChild,
             VARIANT refChild,
             IXMLDOMNode **outNewChild);
        
         HRESULT ( STDMETHODCALLTYPE *replaceChild )( 
            IXMLDOMDocument * This,
             IXMLDOMNode *newChild,
             IXMLDOMNode *oldChild,
             IXMLDOMNode **outOldChild);
        
         HRESULT ( STDMETHODCALLTYPE *removeChild )( 
            IXMLDOMDocument * This,
             IXMLDOMNode *childNode,
             IXMLDOMNode **oldChild);
        
         HRESULT ( STDMETHODCALLTYPE *appendChild )( 
            IXMLDOMDocument * This,
             IXMLDOMNode *newChild,
             IXMLDOMNode **outNewChild);
        
         HRESULT ( STDMETHODCALLTYPE *hasChildNodes )( 
            IXMLDOMDocument * This,
             VARIANT_BOOL *hasChild);
        
         HRESULT ( STDMETHODCALLTYPE *get_ownerDocument )( 
            IXMLDOMDocument * This,
             IXMLDOMDocument **XMLDOMDocument);
        
         HRESULT ( STDMETHODCALLTYPE *cloneNode )( 
            IXMLDOMDocument * This,
             VARIANT_BOOL deep,
             IXMLDOMNode **cloneRoot);
        
         HRESULT ( STDMETHODCALLTYPE *get_nodeTypeString )( 
            IXMLDOMDocument * This,
             BSTR *nodeType);
        
         HRESULT ( STDMETHODCALLTYPE *get_text )( 
            IXMLDOMDocument * This,
             BSTR *text);
        
         HRESULT ( STDMETHODCALLTYPE *put_text )( 
            IXMLDOMDocument * This,
             BSTR text);
        
         HRESULT ( STDMETHODCALLTYPE *get_specified )( 
            IXMLDOMDocument * This,
             VARIANT_BOOL *isSpecified);
        
         HRESULT ( STDMETHODCALLTYPE *get_definition )( 
            IXMLDOMDocument * This,
             IXMLDOMNode **definitionNode);
        
         HRESULT ( STDMETHODCALLTYPE *get_nodeTypedValue )( 
            IXMLDOMDocument * This,
             VARIANT *typedValue);
        
         HRESULT ( STDMETHODCALLTYPE *put_nodeTypedValue )( 
            IXMLDOMDocument * This,
             VARIANT typedValue);
        
         HRESULT ( STDMETHODCALLTYPE *get_dataType )( 
            IXMLDOMDocument * This,
             VARIANT *dataTypeName);
        
         HRESULT ( STDMETHODCALLTYPE *put_dataType )( 
            IXMLDOMDocument * This,
             BSTR dataTypeName);
        
         HRESULT ( STDMETHODCALLTYPE *get_xml )( 
            IXMLDOMDocument * This,
             BSTR *xmlString);
        
         HRESULT ( STDMETHODCALLTYPE *transformNode )( 
            IXMLDOMDocument * This,
             IXMLDOMNode *stylesheet,
             BSTR *xmlString);
        
         HRESULT ( STDMETHODCALLTYPE *selectNodes )( 
            IXMLDOMDocument * This,
             BSTR queryString,
             IXMLDOMNodeList **resultList);
        
         HRESULT ( STDMETHODCALLTYPE *selectSingleNode )( 
            IXMLDOMDocument * This,
             BSTR queryString,
             IXMLDOMNode **resultNode);
        
         HRESULT ( STDMETHODCALLTYPE *get_parsed )( 
            IXMLDOMDocument * This,
             VARIANT_BOOL *isParsed);
        
         HRESULT ( STDMETHODCALLTYPE *get_namespaceURI )( 
            IXMLDOMDocument * This,
             BSTR *namespaceURI);
        
         HRESULT ( STDMETHODCALLTYPE *get_prefix )( 
            IXMLDOMDocument * This,
             BSTR *prefixString);
        
         HRESULT ( STDMETHODCALLTYPE *get_baseName )( 
            IXMLDOMDocument * This,
             BSTR *nameString);
        
         HRESULT ( STDMETHODCALLTYPE *transformNodeToObject )( 
            IXMLDOMDocument * This,
             IXMLDOMNode *stylesheet,
             VARIANT outputObject);
        
         HRESULT ( STDMETHODCALLTYPE *get_doctype )( 
            IXMLDOMDocument * This,
             IXMLDOMDocumentType **documentType);
        
         HRESULT ( STDMETHODCALLTYPE *get_implementation )( 
            IXMLDOMDocument * This,
             IXMLDOMImplementation **impl);
        
         HRESULT ( STDMETHODCALLTYPE *get_documentElement )( 
            IXMLDOMDocument * This,
             IXMLDOMElement **DOMElement);
        
         HRESULT ( STDMETHODCALLTYPE *putref_documentElement )( 
            IXMLDOMDocument * This,
             IXMLDOMElement *DOMElement);
        
         HRESULT ( STDMETHODCALLTYPE *createElement )( 
            IXMLDOMDocument * This,
             BSTR tagName,
             IXMLDOMElement **element);
        
         HRESULT ( STDMETHODCALLTYPE *createDocumentFragment )( 
            IXMLDOMDocument * This,
             IXMLDOMDocumentFragment **docFrag);
        
         HRESULT ( STDMETHODCALLTYPE *createTextNode )( 
            IXMLDOMDocument * This,
             BSTR data,
             IXMLDOMText **text);
        
         HRESULT ( STDMETHODCALLTYPE *createComment )( 
            IXMLDOMDocument * This,
             BSTR data,
             IXMLDOMComment **comment);
        
         HRESULT ( STDMETHODCALLTYPE *createCDATASection )( 
            IXMLDOMDocument * This,
             BSTR data,
             IXMLDOMCDATASection **cdata);
        
         HRESULT ( STDMETHODCALLTYPE *createProcessingInstruction )( 
            IXMLDOMDocument * This,
             BSTR target,
             BSTR data,
             IXMLDOMProcessingInstruction **pi);
        
         HRESULT ( STDMETHODCALLTYPE *createAttribute )( 
            IXMLDOMDocument * This,
             BSTR name,
             IXMLDOMAttribute **attribute);
        
         HRESULT ( STDMETHODCALLTYPE *createEntityReference )( 
            IXMLDOMDocument * This,
             BSTR name,
             IXMLDOMEntityReference **entityRef);
        
         HRESULT ( STDMETHODCALLTYPE *getElementsByTagName )( 
            IXMLDOMDocument * This,
             BSTR tagName,
             IXMLDOMNodeList **resultList);
        
         HRESULT ( STDMETHODCALLTYPE *createNode )( 
            IXMLDOMDocument * This,
             VARIANT Type,
             BSTR name,
             BSTR namespaceURI,
             IXMLDOMNode **node);
        
         HRESULT ( STDMETHODCALLTYPE *nodeFromID )( 
            IXMLDOMDocument * This,
             BSTR idString,
             IXMLDOMNode **node);
        
         HRESULT ( STDMETHODCALLTYPE *load )( 
            IXMLDOMDocument * This,
             VARIANT xmlSource,
             VARIANT_BOOL *isSuccessful);
        
         HRESULT ( STDMETHODCALLTYPE *get_readyState )( 
            IXMLDOMDocument * This,
             long *value);
        
         HRESULT ( STDMETHODCALLTYPE *get_parseError )( 
            IXMLDOMDocument * This,
             IXMLDOMParseError **errorObj);
        
         HRESULT ( STDMETHODCALLTYPE *get_url )( 
            IXMLDOMDocument * This,
             BSTR *urlString);
        
         HRESULT ( STDMETHODCALLTYPE *get_async )( 
            IXMLDOMDocument * This,
             VARIANT_BOOL *isAsync);
        
         HRESULT ( STDMETHODCALLTYPE *put_async )( 
            IXMLDOMDocument * This,
             VARIANT_BOOL isAsync);
        
         HRESULT ( STDMETHODCALLTYPE *abort )( 
            IXMLDOMDocument * This);
        
         HRESULT ( STDMETHODCALLTYPE *loadXML )( 
            IXMLDOMDocument * This,
             BSTR bstrXML,
             VARIANT_BOOL *isSuccessful);
        
         HRESULT ( STDMETHODCALLTYPE *save )( 
            IXMLDOMDocument * This,
             VARIANT destination);
        
         HRESULT ( STDMETHODCALLTYPE *get_validateOnParse )( 
            IXMLDOMDocument * This,
             VARIANT_BOOL *isValidating);
        
         HRESULT ( STDMETHODCALLTYPE *put_validateOnParse )( 
            IXMLDOMDocument * This,
             VARIANT_BOOL isValidating);
        
         HRESULT ( STDMETHODCALLTYPE *get_resolveExternals )( 
            IXMLDOMDocument * This,
             VARIANT_BOOL *isResolving);
        
         HRESULT ( STDMETHODCALLTYPE *put_resolveExternals )( 
            IXMLDOMDocument * This,
             VARIANT_BOOL isResolving);
        
         HRESULT ( STDMETHODCALLTYPE *get_preserveWhiteSpace )( 
            IXMLDOMDocument * This,
             VARIANT_BOOL *isPreserving);
        
         HRESULT ( STDMETHODCALLTYPE *put_preserveWhiteSpace )( 
            IXMLDOMDocument * This,
             VARIANT_BOOL isPreserving);
        
         HRESULT ( STDMETHODCALLTYPE *put_onreadystatechange )( 
            IXMLDOMDocument * This,
             VARIANT readystatechangeSink);
        
         HRESULT ( STDMETHODCALLTYPE *put_ondataavailable )( 
            IXMLDOMDocument * This,
             VARIANT ondataavailableSink);
        
         HRESULT ( STDMETHODCALLTYPE *put_ontransformnode )( 
            IXMLDOMDocument * This,
             VARIANT ontransformnodeSink);
        
        END_INTERFACE
    } IXMLDOMDocumentVtbl;

    typedef struct _IXMLDOMDocument {
        IXMLDOMDocumentVtbl *lpVtbl;
    } XMLDomDocument;*/