using Newtonsoft.Json;
using System.Text;

public class CohereService
{
    private readonly HttpClient _client;

    public CohereService(string apiKey)
    {
        _client = new HttpClient();
        _client.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}");
    }


    public async Task<string> GetChatResponseAsync(string userMessage)
    {
        var requestPayload = new
        {
            model = "command-r-plus",
            prompt = userMessage,
            max_tokens = 100,  // You can adjust this as needed
            temperature = 0 // Adjust for creative output
        };

        var content = new StringContent(JsonConvert.SerializeObject(requestPayload), Encoding.UTF8, "application/json");

        // Update this to the correct chat or generation endpoint based on Cohere's documentation
        var response = await _client.PostAsync("https://api.cohere.ai/generate", content);

        if (!response.IsSuccessStatusCode)
        {
            var errorResponse = await response.Content.ReadAsStringAsync();
            throw new HttpRequestException($"Error calling Cohere API: {response.StatusCode} - {errorResponse}");
        }

        var responseContent = await response.Content.ReadAsStringAsync();
        dynamic responseJson = JsonConvert.DeserializeObject(responseContent);

        if (responseJson == null || responseJson.text == null)
        {
            throw new Exception("Invalid response from Cohere API");
        }

        return responseJson.text.ToString().Trim();
    }


}
