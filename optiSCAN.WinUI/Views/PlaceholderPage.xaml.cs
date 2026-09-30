using Microsoft.UI.Xaml.Controls;

namespace optiSCAN.WinUI.Views;

public sealed partial class PlaceholderPage : Page
{
    public PlaceholderPage(string title, string body)
    {
        InitializeComponent();
        TitleText.Text = title;
        BodyText.Text = body;
    }
}
