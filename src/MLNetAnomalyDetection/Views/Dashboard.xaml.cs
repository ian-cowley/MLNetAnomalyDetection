using System.ComponentModel;
using System.Windows;
using MLNetAnomalyDetection.ViewModels;

namespace MLNetAnomalyDetection.Views
{
    public partial class Dashboard : Window
    {
        public DashboardViewModel ViewModel { get; }

        public Dashboard(DashboardViewModel viewModel)
        {
            InitializeComponent();
            ViewModel = viewModel;
            DataContext = ViewModel;
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            // Hide the window instead of closing it, so we can re-open it quickly from the tray
            e.Cancel = true;
            this.Hide();
        }
    }
}
